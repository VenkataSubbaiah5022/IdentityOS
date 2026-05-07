import crypto from "crypto";
import express from "express";
import { RoleName } from "@prisma/client";
import { hashValue, verifyHash, verifyToken } from "@identityos/security";
import { z } from "zod";
import { prisma } from "../../lib/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";
import { validate } from "../../middleware/validate";
import { env } from "../../config/env";

const appSchema = z.object({
  name: z.string().min(2).max(50),
  callbackUrls: z.array(z.string().url()).min(1),
});

export const appRegistryRouter = express.Router();

appRegistryRouter.post(
  "/register",
  requireAuth,
  requireRole(RoleName.ADMIN, RoleName.SUPER_ADMIN),
  validate(appSchema),
  async (req, res) => {
    const clientId = crypto.randomBytes(16).toString("hex");
    const clientSecret = crypto.randomBytes(32).toString("hex");
    const app = await prisma.appClient.create({
      data: {
        name: req.body.name,
        clientId,
        clientSecretHash: await hashValue(clientSecret),
        callbackUrls: req.body.callbackUrls,
      },
    });
    res.status(201).json({ ...app, clientSecret });
  },
);

appRegistryRouter.get("/", requireAuth, requireRole(RoleName.ADMIN, RoleName.SUPER_ADMIN), async (_req, res) => {
  const apps = await prisma.appClient.findMany({
    select: { id: true, name: true, clientId: true, callbackUrls: true, createdAt: true, updatedAt: true },
  });
  res.json(apps);
});

appRegistryRouter.patch(
  "/:id",
  requireAuth,
  requireRole(RoleName.ADMIN, RoleName.SUPER_ADMIN),
  validate(appSchema.partial()),
  async (req, res) => {
    const app = await prisma.appClient.update({
      where: { id: req.params.id },
      data: req.body,
      select: { id: true, name: true, clientId: true, callbackUrls: true, updatedAt: true },
    });
    res.json(app);
  },
);

appRegistryRouter.post("/token/introspect", async (req, res) => {
  const { clientId, clientSecret, token } = req.body ?? {};
  if (!clientId || !clientSecret || !token) {
    return res.status(400).json({ error: "Missing credentials or token" });
  }
  const app = await prisma.appClient.findUnique({ where: { clientId } });
  if (!app || !(await verifyHash(app.clientSecretHash, clientSecret))) {
    return res.status(401).json({ error: "Invalid client credentials" });
  }
  try {
    const payload = verifyToken<{ sub: string; sessionId: string; roles: string[] }>(
      token,
      env.jwtAccessSecret,
    );
    return res.json({ active: true, sub: payload.sub, sessionId: payload.sessionId, roles: payload.roles });
  } catch {
    return res.json({ active: false });
  }
});
