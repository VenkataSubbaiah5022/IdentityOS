import express from "express";
import { RoleName } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../../lib/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";
import { validate } from "../../middleware/validate";

const createRoleSchema = z.object({
  name: z.nativeEnum(RoleName),
  description: z.string().max(100).optional(),
});

export const rolesRouter = express.Router();

rolesRouter.get("/", requireAuth, requireRole(RoleName.ADMIN, RoleName.SUPER_ADMIN), async (_req, res) => {
  const roles = await prisma.role.findMany({ include: { permissions: { include: { permission: true } } } });
  res.json(roles);
});

rolesRouter.post(
  "/",
  requireAuth,
  requireRole(RoleName.SUPER_ADMIN),
  validate(createRoleSchema),
  async (req, res) => {
    const role = await prisma.role.upsert({
      where: { name: req.body.name },
      update: { description: req.body.description },
      create: req.body,
    });
    res.status(201).json(role);
  },
);

rolesRouter.patch(
  "/:id",
  requireAuth,
  requireRole(RoleName.SUPER_ADMIN),
  async (req, res) => {
    const role = await prisma.role.update({
      where: { id: req.params.id },
      data: { description: req.body.description },
    });
    res.json(role);
  },
);
