import express from "express";
import { RoleName } from "@prisma/client";
import { prisma } from "../../lib/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";

export const adminRouter = express.Router();

adminRouter.get("/users", requireAuth, requireRole(RoleName.ADMIN, RoleName.SUPER_ADMIN), async (_req, res) => {
  const users = await prisma.user.findMany({
    select: { id: true, email: true, username: true, createdAt: true, emailVerified: true },
    orderBy: { createdAt: "desc" },
  });
  res.json(users);
});

adminRouter.get("/logs", requireAuth, requireRole(RoleName.ADMIN, RoleName.SUPER_ADMIN), async (_req, res) => {
  const logs = await prisma.auditLog.findMany({ orderBy: { createdAt: "desc" }, take: 100 });
  res.json(logs);
});

adminRouter.delete(
  "/users/:id",
  requireAuth,
  requireRole(RoleName.SUPER_ADMIN),
  async (req, res) => {
    await prisma.user.delete({ where: { id: req.params.id } });
    res.json({ ok: true });
  },
);
