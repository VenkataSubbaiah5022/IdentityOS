import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { env } from "./config/env";
import { prisma } from "./lib/prisma";
import { redis } from "./lib/redis";
import { authRouter } from "./modules/auth/routes";
import { usersRouter } from "./modules/users/routes";
import { sessionsRouter } from "./modules/sessions/routes";
import { rolesRouter } from "./modules/roles/routes";
import { appRegistryRouter } from "./modules/apps/routes";
import { adminRouter } from "./modules/admin/routes";
import { requestLogger } from "./middleware/request-log";

export const app = express();

app.use(helmet());
app.use(requestLogger);
app.use(
  cors({
    origin: [env.frontendOrigin, env.adminWebOrigin],
    credentials: true,
  }),
);
app.use(express.json());
app.use(cookieParser());
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    standardHeaders: true,
  }),
);

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "IdentityOS", env: env.nodeEnv });
});

app.get("/ready", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    await redis.ping();
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.use("/auth", authRouter);
app.use("/users", usersRouter);
app.use("/sessions", sessionsRouter);
app.use("/roles", rolesRouter);
app.use("/apps", appRegistryRouter);
app.use("/admin", adminRouter);
