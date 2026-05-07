import express from "express";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
  verifyEmailSchema,
} from "@identityos/contracts";
import { validate } from "../../middleware/validate";
import { env } from "../../config/env";
import {
  createEmailVerificationToken,
  login,
  loginFromOauth,
  logout,
  register,
  requestPasswordReset,
  resetPassword,
  rotateRefreshToken,
  verifyEmail,
} from "./service";
import { consumeOauthState, createOauthState } from "./oauth";
import { requireCsrf, setCsrfCookie } from "../../middleware/csrf";
import { prisma } from "../../lib/prisma";

export const authRouter = express.Router();

authRouter.post("/register", validate(registerSchema), async (req, res) => {
  try {
    const { user, verificationToken } = await register(req.body.email, req.body.username, req.body.password);
    res.status(201).json({
      id: user.id,
      email: user.email,
      username: user.username,
      message: "Account created. Verify your email to continue.",
      verificationToken: env.nodeEnv === "development" ? verificationToken : undefined,
    });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

authRouter.post("/login", validate(loginSchema), async (req, res) => {
  try {
    const data = await login(req.body.email, req.body.password, req.ip, req.headers["user-agent"]);
    const csrfToken = setCsrfCookie(req, res);
    res.cookie("refreshToken", data.refreshToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: env.nodeEnv === "production",
      path: "/auth",
    });
    res.json({
      accessToken: data.accessToken,
      csrfToken,
      user: { id: data.user.id, email: data.user.email, username: data.user.username },
    });
  } catch (error) {
    res.status(401).json({ error: (error as Error).message });
  }
});

authRouter.post("/refresh-token", requireCsrf, async (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken;
  if (!token) return res.status(401).json({ error: "Missing refresh token" });
  try {
    const data = await rotateRefreshToken(token);
    res.cookie("refreshToken", data.refreshToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: env.nodeEnv === "production",
      path: "/auth",
    });
    return res.json({ accessToken: data.accessToken });
  } catch (error) {
    return res.status(401).json({ error: (error as Error).message });
  }
});

authRouter.post("/logout", requireCsrf, async (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken;
  if (token) {
    try {
      await logout(token);
    } catch {
      // Always return success to avoid token probing.
    }
  }
  res.clearCookie("refreshToken", { path: "/auth" });
  res.clearCookie("csrfToken", { path: "/" });
  return res.json({ ok: true });
});

authRouter.post("/forgot-password", validate(forgotPasswordSchema), async (req, res) => {
  const token = await requestPasswordReset(req.body.email);
  res.json({
    message: "If the account exists, a reset link will be sent.",
    resetToken: env.nodeEnv === "development" ? token : undefined,
  });
});

authRouter.post("/reset-password", validate(resetPasswordSchema), async (req, res) => {
  try {
    await resetPassword(req.body.token, req.body.password);
    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

authRouter.post("/verify-email", validate(verifyEmailSchema), async (req, res) => {
  try {
    await verifyEmail(req.body.token);
    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

authRouter.post("/resend-verification", validate(forgotPasswordSchema), async (req, res) => {
  const userEmail = req.body.email as string;
  // Reuse email schema for payload shape to avoid duplicate contracts.
  // On real mail provider integration, emit message rather than returning token.
  const user = await prisma.user.findUnique({ where: { email: userEmail } });
  if (!user) return res.json({ message: "If the account exists, verification will be sent." });
  const token = await createEmailVerificationToken(user.id);
  return res.json({
    message: "Verification token created.",
    verificationToken: env.nodeEnv === "development" ? token : undefined,
  });
});

authRouter.get("/google", async (_req, res) => {
  if (!env.googleClientId || !env.googleCallbackUrl) {
    return res.status(400).json({ error: "Google OAuth not configured" });
  }
  const state = await createOauthState("google");
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", env.googleClientId);
  url.searchParams.set("redirect_uri", env.googleCallbackUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

authRouter.get("/google/callback", async (req, res) => {
  const state = String(req.query.state ?? "");
  const code = String(req.query.code ?? "");
  if (!state || !code || !(await consumeOauthState("google", state))) {
    return res.status(400).json({ error: "Invalid OAuth state" });
  }
  if (!env.googleClientId || !env.googleClientSecret || !env.googleCallbackUrl) {
    return res.status(400).json({ error: "Google OAuth not configured" });
  }

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.googleClientId,
      client_secret: env.googleClientSecret,
      redirect_uri: env.googleCallbackUrl,
      grant_type: "authorization_code",
    }),
  });
  if (!tokenRes.ok) return res.status(401).json({ error: "Google token exchange failed" });
  const tokenJson = (await tokenRes.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
  };

  const profileRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });
  if (!profileRes.ok) return res.status(401).json({ error: "Google userinfo fetch failed" });
  const profile = (await profileRes.json()) as { sub: string; email: string; name?: string };

  const usernameBase = (profile.name ?? profile.email.split("@")[0]).replace(/\s+/g, "").toLowerCase();
  const username = `${usernameBase}-${profile.sub.slice(0, 6)}`;
  const sessionData = await loginFromOauth(
    "google",
    profile.sub,
    profile.email,
    username,
    tokenJson.access_token,
    tokenJson.refresh_token,
    req.ip,
    req.headers["user-agent"],
  );

  const csrfToken = setCsrfCookie(req, res);
  res.cookie("refreshToken", sessionData.refreshToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: env.nodeEnv === "production",
    path: "/auth",
  });
  return res.redirect(`${env.adminWebOrigin}/oauth/success?accessToken=${sessionData.accessToken}&csrfToken=${csrfToken}`);
});

authRouter.get("/github", async (_req, res) => {
  if (!env.githubClientId || !env.githubCallbackUrl) {
    return res.status(400).json({ error: "GitHub OAuth not configured" });
  }
  const state = await createOauthState("github");
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", env.githubClientId);
  url.searchParams.set("redirect_uri", env.githubCallbackUrl);
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

authRouter.get("/github/callback", async (req, res) => {
  const state = String(req.query.state ?? "");
  const code = String(req.query.code ?? "");
  if (!state || !code || !(await consumeOauthState("github", state))) {
    return res.status(400).json({ error: "Invalid OAuth state" });
  }
  if (!env.githubClientId || !env.githubClientSecret || !env.githubCallbackUrl) {
    return res.status(400).json({ error: "GitHub OAuth not configured" });
  }

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({
      code,
      client_id: env.githubClientId,
      client_secret: env.githubClientSecret,
      redirect_uri: env.githubCallbackUrl,
    }),
  });
  if (!tokenRes.ok) return res.status(401).json({ error: "GitHub token exchange failed" });
  const tokenJson = (await tokenRes.json()) as { access_token: string };

  const userRes = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${tokenJson.access_token}`, Accept: "application/vnd.github+json" },
  });
  if (!userRes.ok) return res.status(401).json({ error: "GitHub user fetch failed" });
  const user = (await userRes.json()) as { id: number; login: string; email: string | null };

  let email = user.email;
  if (!email) {
    const emailsRes = await fetch("https://api.github.com/user/emails", {
      headers: { Authorization: `Bearer ${tokenJson.access_token}`, Accept: "application/vnd.github+json" },
    });
    if (emailsRes.ok) {
      const emails = (await emailsRes.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
      email = emails.find((e) => e.primary && e.verified)?.email ?? emails[0]?.email ?? null;
    }
  }
  if (!email) return res.status(400).json({ error: "GitHub account has no accessible email" });

  const sessionData = await loginFromOauth(
    "github",
    String(user.id),
    email,
    user.login,
    tokenJson.access_token,
    undefined,
    req.ip,
    req.headers["user-agent"],
  );

  const csrfToken = setCsrfCookie(req, res);
  res.cookie("refreshToken", sessionData.refreshToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: env.nodeEnv === "production",
    path: "/auth",
  });
  return res.redirect(`${env.adminWebOrigin}/oauth/success?accessToken=${sessionData.accessToken}&csrfToken=${csrfToken}`);
});
