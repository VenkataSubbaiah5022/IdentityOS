import { RoleName } from "@prisma/client";
import { NextFunction, Request, Response } from "express";

export const requireRole =
  (...allowed: RoleName[]) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (!req.roles || !req.roles.some((role) => allowed.includes(role))) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }
    next();
  };
