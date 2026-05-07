import { NextFunction, Request, Response } from "express";
import { RoleName } from "@prisma/client";
import { verifyToken } from "@identityos/security";
import { env } from "../config/env";

interface AccessPayload {
  sub: string;
  sessionId: string;
  roles: RoleName[];
}

export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing token" });
    return;
  }

  try {
    const payload = verifyToken<AccessPayload>(auth.slice(7), env.jwtAccessSecret);
    req.userId = payload.sub;
    req.sessionId = payload.sessionId;
    req.roles = payload.roles;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};
