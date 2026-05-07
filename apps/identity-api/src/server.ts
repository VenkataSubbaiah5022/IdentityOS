import { app } from "./app";
import { env } from "./config/env";
import { prisma } from "./lib/prisma";
import { redis } from "./lib/redis";

const server = app.listen(env.port, () => {
  console.log(`IdentityOS API running on http://localhost:${env.port}`);
});

const shutdown = async () => {
  console.log("Shutting down IdentityOS API...");
  server.close();
  await prisma.$disconnect();
  redis.disconnect();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
