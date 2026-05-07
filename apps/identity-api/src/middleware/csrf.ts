import crypto from "crypto";
import { NextFunction, Request, Response } from "express";

export const setCsrfCookie = (_req: Request, res: Response): string => {
  const token = crypto.randomBytes(24).toString("hex");
  res.cookie("csrfToken", token, {
    httpOnly: false,
    sameSite: "lax",
    secure: false,
    path: "/",
  });
  return token;
};

export const requireCsrf = (req: Request, res: Response, next: NextFunction): void => {
  const cookieToken = req.cookies.csrfToken;
  const headerToken = req.headers["x-csrf-token"];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    res.status(403).json({ error: "Invalid CSRF token" });
    return;
  }
  next();
};
