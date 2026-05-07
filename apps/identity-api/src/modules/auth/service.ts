import crypto from "crypto";
import { AuditAction, RoleName } from "@prisma/client";
import {
  hashValue,
  signAccessToken,
  signRefreshToken,
  verifyHash,
  verifyToken,
} from "@identityos/security";
import { prisma } from "../../lib/prisma";
import { env } from "../../config/env";

const daysFromNow = (days: number): Date => new Date(Date.now() + days * 24 * 60 * 60 * 1000);
const hashToken = async (token: string): Promise<string> => hashValue(token);

export const register = async (email: string, username: string, password: string) => {
  const existing = await prisma.user.findFirst({ where: { OR: [{ email }, { username }] } });
  if (existing) throw new Error("User already exists");
  const passwordHash = await hashValue(password);
  const user = await prisma.user.create({
    data: { email, username, passwordHash },
  });

  const role = await prisma.role.findUnique({ where: { name: RoleName.USER } });
  if (role) {
    await prisma.userRole.create({ data: { userId: user.id, roleId: role.id } });
  }
  await prisma.auditLog.create({
    data: { userId: user.id, action: AuditAction.REGISTER },
  });

  return user;
};

export const login = async (email: string, password: string, ipAddress?: string, userAgent?: string) => {
  const user = await prisma.user.findUnique({
    where: { email },
    include: { roles: { include: { role: true } } },
  });
  if (!user) throw new Error("Invalid credentials");

  const ok = await verifyHash(user.passwordHash, password);
  if (!ok) throw new Error("Invalid credentials");

  const session = await prisma.session.create({
    data: {
      userId: user.id,
      ipAddress,
      userAgent,
      expiresAt: daysFromNow(env.refreshTokenTtlDays),
    },
  });

  const roles = user.roles.map((r) => r.role.name);
  const accessToken = signAccessToken(
    { sub: user.id, sessionId: session.id, roles },
    env.jwtAccessSecret,
    env.accessTokenTtl,
  );
  const refreshToken = signRefreshToken(
    { sub: user.id, sessionId: session.id },
    env.jwtRefreshSecret,
    `${env.refreshTokenTtlDays}d`,
  );

  await prisma.refreshToken.create({
    data: {
      sessionId: session.id,
      tokenHash: await hashToken(refreshToken),
      expiresAt: daysFromNow(env.refreshTokenTtlDays),
    },
  });
  await prisma.auditLog.create({
    data: { userId: user.id, action: AuditAction.LOGIN, ipAddress, metadata: { userAgent } },
  });

  return { user, accessToken, refreshToken };
};

export const rotateRefreshToken = async (incomingToken: string) => {
  const payload = verifyToken<{ sub: string; sessionId: string }>(incomingToken, env.jwtRefreshSecret);
  const tokens = await prisma.refreshToken.findMany({
    where: { sessionId: payload.sessionId, revokedAt: null },
    orderBy: { createdAt: "desc" },
    take: 5,
  });

  let currentToken = null;
  for (const token of tokens) {
    const match = await verifyHash(token.tokenHash, incomingToken);
    if (match) {
      currentToken = token;
      break;
    }
  }
  if (!currentToken) throw new Error("Invalid refresh token");

  if (currentToken.expiresAt < new Date()) throw new Error("Refresh token expired");

  const user = await prisma.user.findUnique({
    where: { id: payload.sub },
    include: { roles: { include: { role: true } } },
  });
  if (!user) throw new Error("User not found");

  const newRefreshToken = signRefreshToken(
    { sub: payload.sub, sessionId: payload.sessionId },
    env.jwtRefreshSecret,
    `${env.refreshTokenTtlDays}d`,
  );
  const newAccessToken = signAccessToken(
    {
      sub: user.id,
      sessionId: payload.sessionId,
      roles: user.roles.map((r) => r.role.name),
    },
    env.jwtAccessSecret,
    env.accessTokenTtl,
  );

  const replacement = await prisma.refreshToken.create({
    data: {
      sessionId: payload.sessionId,
      tokenHash: await hashToken(newRefreshToken),
      expiresAt: daysFromNow(env.refreshTokenTtlDays),
      rotatedFrom: currentToken.id,
    },
  });

  await prisma.refreshToken.update({
    where: { id: currentToken.id },
    data: { revokedAt: new Date(), replacedBy: replacement.id },
  });

  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
};

export const logout = async (refreshToken: string) => {
  const payload = verifyToken<{ sessionId: string }>(refreshToken, env.jwtRefreshSecret);
  await prisma.refreshToken.updateMany({
    where: { sessionId: payload.sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  await prisma.session.update({
    where: { id: payload.sessionId },
    data: { revokedAt: new Date() },
  });
  await prisma.auditLog.create({
    data: { action: AuditAction.LOGOUT, metadata: { sessionId: payload.sessionId } },
  });
};

export const requestPasswordReset = async (email: string) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return null;
  const rawToken = crypto.randomBytes(24).toString("hex");
  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      tokenHash: await hashToken(rawToken),
      expiresAt: new Date(Date.now() + 1000 * 60 * 30),
    },
  });
  return rawToken;
};

export const resetPassword = async (token: string, password: string) => {
  const candidates = await prisma.passwordResetToken.findMany({
    where: { usedAt: null, expiresAt: { gt: new Date() } },
    include: { user: true },
    orderBy: { createdAt: "desc" },
    take: 10,
  });
  const match = await (async () => {
    for (const c of candidates) {
      if (await verifyHash(c.tokenHash, token)) return c;
    }
    return null;
  })();
  if (!match) throw new Error("Invalid reset token");

  await prisma.user.update({
    where: { id: match.userId },
    data: { passwordHash: await hashValue(password) },
  });
  await prisma.passwordResetToken.update({
    where: { id: match.id },
    data: { usedAt: new Date() },
  });
  await prisma.auditLog.create({
    data: { userId: match.userId, action: AuditAction.PASSWORD_RESET },
  });
};
