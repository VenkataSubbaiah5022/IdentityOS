import dotenv from "dotenv";

dotenv.config();

const must = (value: string | undefined, key: string): string => {
  if (!value) throw new Error(`Missing env var: ${key}`);
  return value;
};

export const env = {
  port: Number(process.env.PORT ?? 4000),
  nodeEnv: process.env.NODE_ENV ?? "development",
  databaseUrl: must(process.env.DATABASE_URL, "DATABASE_URL"),
  redisUrl: must(process.env.REDIS_URL, "REDIS_URL"),
  jwtAccessSecret: must(process.env.JWT_ACCESS_SECRET, "JWT_ACCESS_SECRET"),
  jwtRefreshSecret: must(process.env.JWT_REFRESH_SECRET, "JWT_REFRESH_SECRET"),
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL ?? "15m",
  refreshTokenTtlDays: Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 30),
  frontendOrigin: process.env.FRONTEND_ORIGIN ?? "http://localhost:3000",
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
  googleCallbackUrl: process.env.GOOGLE_CALLBACK_URL,
  githubClientId: process.env.GITHUB_CLIENT_ID,
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
  githubCallbackUrl: process.env.GITHUB_CALLBACK_URL,
};
