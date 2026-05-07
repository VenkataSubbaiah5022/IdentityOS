import { RoleName } from "@prisma/client";

declare global {
  namespace Express {
    interface Request {
      userId?: string;
      sessionId?: string;
      roles?: RoleName[];
    }
  }
}

export {};
