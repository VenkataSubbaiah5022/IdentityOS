import express from "express";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
} from "@identityos/contracts";
import { validate } from "../../middleware/validate";
import { env } from "../../config/env";
import {
  login,
  logout,
  register,
  requestPasswordReset,
  resetPassword,
  rotateRefreshToken,
} from "./service";
import { consumeOauthState, createOauthState } from "./oauth";

export const authRouter = express.Router();

authRouter.post("/register", validate(registerSchema), async (req, res) => {
  try {
    const user = await register(req.body.email, req.body.username, req.body.password);
    res.status(201).json({ id: user.id, email: user.email, username: user.username });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

authRouter.post("/login", validate(loginSchema), async (req, res) => {
  try {
    const data = await login(req.body.email, req.body.password, req.ip, req.headers["user-agent"]);
    res.cookie("refreshToken", data.refreshToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      path: "/auth",
    });
    res.json({
      accessToken: data.accessToken,
      user: { id: data.user.id, email: data.user.email, username: data.user.username },
    });
  } catch (error) {
    res.status(401).json({ error: (error as Error).message });
  }
});

authRouter.post("/refresh-token", async (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken;
  if (!token) return res.status(401).json({ error: "Missing refresh token" });
  try {
    const data = await rotateRefreshToken(token);
    res.cookie("refreshToken", data.refreshToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      path: "/auth",
    });
    return res.json({ accessToken: data.accessToken });
  } catch (error) {
    return res.status(401).json({ error: (error as Error).message });
  }
});

authRouter.post("/logout", async (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken;
  if (token) {
    try {
      await logout(token);
    } catch {
      // Always return success to avoid token probing.
    }
  }
  res.clearCookie("refreshToken", { path: "/auth" });
  return res.json({ ok: true });
});

authRouter.post("/forgot-password", validate(forgotPasswordSchema), async (req, res) => {
  await requestPasswordReset(req.body.email);
  res.json({ message: "If the account exists, a reset link will be sent." });
});

authRouter.post("/reset-password", validate(resetPasswordSchema), async (req, res) => {
  try {
    await resetPassword(req.body.token, req.body.password);
    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
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
  return res.status(501).json({ error: "Token exchange + account linking pending" });
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
  return res.status(501).json({ error: "Token exchange + account linking pending" });
});
