import crypto from "crypto";
import { redis } from "../../lib/redis";

const stateKey = (provider: string, state: string): string => `oauth_state:${provider}:${state}`;

export const createOauthState = async (provider: "google" | "github"): Promise<string> => {
  const state = crypto.randomBytes(16).toString("hex");
  await redis.set(stateKey(provider, state), "1", "EX", 300);
  return state;
};

export const consumeOauthState = async (
  provider: "google" | "github",
  state: string,
): Promise<boolean> => {
  const key = stateKey(provider, state);
  const exists = await redis.get(key);
  if (!exists) return false;
  await redis.del(key);
  return true;
};
