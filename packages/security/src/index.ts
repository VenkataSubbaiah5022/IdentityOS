import argon2 from "argon2";
import jwt from "jsonwebtoken";

export interface TokenPayload {
  sub: string;
  sessionId: string;
  roles: string[];
}

export const hashValue = async (value: string): Promise<string> => argon2.hash(value);

export const verifyHash = async (hash: string, value: string): Promise<boolean> =>
  argon2.verify(hash, value);

export const signAccessToken = (
  payload: TokenPayload,
  secret: string,
  expiresIn: string,
): string => jwt.sign(payload, secret, { expiresIn } as jwt.SignOptions);

export const signRefreshToken = (
  payload: Pick<TokenPayload, "sub" | "sessionId">,
  secret: string,
  expiresIn: string,
): string => jwt.sign(payload, secret, { expiresIn } as jwt.SignOptions);

export const verifyToken = <T>(token: string, secret: string): T =>
  jwt.verify(token, secret) as T;
