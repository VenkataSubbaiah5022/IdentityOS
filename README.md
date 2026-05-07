# IdentityOS

Centralized authentication and identity management platform for all internal applications.

## Quick Start

1. Copy `.env.example` to `.env`.
2. Start infrastructure:
   - `docker compose -f infra/docker/docker-compose.yml up -d`
3. Install dependencies:
   - `npm install`
4. Generate Prisma client and run migration:
   - `npm run prisma:generate`
   - `npm run prisma:migrate`
   - `npm run prisma:seed`
5. Start API:
   - `npm run dev`

## Monorepo

- `apps/identity-api`: Express + Prisma API
- `apps/admin-web`: future admin UI
- `packages/contracts`: Zod schemas and shared contracts
- `packages/security`: password + token utilities
- `infra/docker`: local postgres + redis
- `docs`: architecture and phase notes
