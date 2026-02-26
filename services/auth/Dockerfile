FROM node:20-alpine AS base
WORKDIR /app

# Copy workspace root
COPY package.json ./
COPY packages/shared ./packages/shared
COPY services/auth ./services/auth

# Install all workspace deps
RUN npm install --workspace=services/auth

# ── Production ──
FROM node:20-alpine
WORKDIR /app
COPY --from=base /app .

EXPOSE 3001
CMD ["node", "services/auth/src/server.js"]
