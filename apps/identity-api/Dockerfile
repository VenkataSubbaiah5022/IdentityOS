FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
COPY apps/identity-api/package.json apps/identity-api/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/security/package.json packages/security/package.json
RUN npm install

COPY . .
RUN npm run build -w apps/identity-api

EXPOSE 4000
CMD ["npm", "run", "start", "-w", "apps/identity-api"]
