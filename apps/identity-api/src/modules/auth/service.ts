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
import { redis } from "../../lib/redis";

const daysFromNow = (days: number): Date => new Date(Date.now() + days * 24 * 60 * 60 * 1000);
const minutesFromNow = (minutes: number): Date => new Date(Date.now() + minutes * 60 * 1000);
const hashToken = async (token: string): Promise<string> => hashValue(token);
const loginAttemptKey = (email: string, ipAddress?: string): string =>
  `login_attempt:${email.toLowerCase()}:${ipAddress ?? "unknown"}`;

const issueSessionTokens = async (userId: string, ipAddress?: string, userAgent?: string) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { roles: { include: { role: true } } },
  });
  if (!user) throw new Error("User not found");

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

  return { user, accessToken, refreshToken, sessionId: session.id };
};

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

  const verificationToken = await createEmailVerificationToken(user.id);
  return { user, verificationToken };
};

export const login = async (email: string, password: string, ipAddress?: string, userAgent?: string) => {
  const attemptKey = loginAttemptKey(email, ipAddress);
  const attempts = Number(await redis.get(attemptKey) ?? 0);
  if (attempts >= env.loginRateLimitMax) {
    throw new Error("Too many failed login attempts. Try again later.");
  }

  const user = await prisma.user.findUnique({
    where: { email },
  });
  if (!user) {
    await redis.multi().incr(attemptKey).expire(attemptKey, env.loginRateLimitWindowSeconds).exec();
    throw new Error("Invalid credentials");
  }

  const ok = await verifyHash(user.passwordHash, password);
  if (!ok) {
    await redis.multi().incr(attemptKey).expire(attemptKey, env.loginRateLimitWindowSeconds).exec();
    throw new Error("Invalid credentials");
  }
  await redis.del(attemptKey);

  if (!user.emailVerified) throw new Error("Please verify email before login");
  const { accessToken, refreshToken } = await issueSessionTokens(user.id, ipAddress, userAgent);
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
      expiresAt: minutesFromNow(env.resetTokenTtlMinutes),
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

export const createEmailVerificationToken = async (userId: string): Promise<string> => {
  const rawToken = crypto.randomBytes(24).toString("hex");
  await prisma.emailVerifyToken.create({
    data: {
      userId,
      tokenHash: await hashToken(rawToken),
      expiresAt: minutesFromNow(env.emailVerifyTtlMinutes),
    },
  });
  return rawToken;
};

export const verifyEmail = async (token: string): Promise<void> => {
  const candidates = await prisma.emailVerifyToken.findMany({
    where: { usedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: "desc" },
    take: 10,
  });

  let match: { id: string; userId: string } | null = null;
  for (const candidate of candidates) {
    if (await verifyHash(candidate.tokenHash, token)) {
      match = { id: candidate.id, userId: candidate.userId };
      break;
    }
  }
  if (!match) throw new Error("Invalid verification token");

  await prisma.user.update({
    where: { id: match.userId },
    data: { emailVerified: true },
  });
  await prisma.emailVerifyToken.update({
    where: { id: match.id },
    data: { usedAt: new Date() },
  });
};

export const loginFromOauth = async (
  provider: "google" | "github",
  providerAccountId: string,
  email: string,
  username: string,
  accessToken: string,
  refreshToken?: string,
  ipAddress?: string,
  userAgent?: string,
) => {
  const existingOauth = await prisma.oauthAccount.findUnique({
    where: { provider_providerAccountId: { provider, providerAccountId } },
    include: { user: true },
  });

  let userId: string;
  if (existingOauth) {
    userId = existingOauth.userId;
    await prisma.oauthAccount.update({
      where: { id: existingOauth.id },
      data: { accessToken, refreshToken },
    });
  } else {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      userId = existingUser.id;
    } else {
      const randomPassword = crypto.randomBytes(32).toString("hex");
      const user = await prisma.user.create({
        data: {
          email,
          username,
          passwordHash: await hashValue(randomPassword),
          emailVerified: true,
        },
      });
      const role = await prisma.role.findUnique({ where: { name: RoleName.USER } });
      if (role) await prisma.userRole.create({ data: { userId: user.id, roleId: role.id } });
      userId = user.id;
    }

    await prisma.oauthAccount.create({
      data: {
        userId,
        provider,
        providerAccountId,
        accessToken,
        refreshToken,
      },
    });
  }

  const tokens = await issueSessionTokens(userId, ipAddress, userAgent);
  await prisma.auditLog.create({
    data: { userId, action: AuditAction.LOGIN, ipAddress, metadata: { provider, oauth: true } },
  });
  return tokens;
};
