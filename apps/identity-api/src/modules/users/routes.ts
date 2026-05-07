import express from "express";
import { z } from "zod";
import { prisma } from "../../lib/prisma";
import { requireAuth } from "../../middleware/auth";
import { validate } from "../../middleware/validate";

const profileSchema = z.object({
  username: z.string().min(3).max(32).optional(),
  avatar: z.string().url().optional(),
  bio: z.string().max(200).optional(),
});

export const usersRouter = express.Router();

usersRouter.get("/me", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.userId },
    select: { id: true, email: true, username: true, avatar: true, bio: true, createdAt: true },
  });
  res.json(user);
});

usersRouter.patch("/profile", requireAuth, validate(profileSchema), async (req, res) => {
  const user = await prisma.user.update({
    where: { id: req.userId },
    data: req.body,
    select: { id: true, email: true, username: true, avatar: true, bio: true },
  });
  res.json(user);
});

usersRouter.delete("/account", requireAuth, async (req, res) => {
  await prisma.user.delete({ where: { id: req.userId } });
  res.json({ ok: true });
});
