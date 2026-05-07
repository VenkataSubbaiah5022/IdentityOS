import express from "express";
import { prisma } from "../../lib/prisma";
import { requireAuth } from "../../middleware/auth";

export const sessionsRouter = express.Router();

sessionsRouter.get("/", requireAuth, async (req, res) => {
  const sessions = await prisma.session.findMany({
    where: { userId: req.userId },
    orderBy: { createdAt: "desc" },
  });
  res.json(sessions);
});

sessionsRouter.delete("/:id", requireAuth, async (req, res) => {
  await prisma.session.updateMany({
    where: { id: req.params.id, userId: req.userId },
    data: { revokedAt: new Date() },
  });
  await prisma.refreshToken.updateMany({
    where: { sessionId: req.params.id, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  res.json({ ok: true });
});
