FROM node:20-alpine AS base
WORKDIR /app

COPY package.json ./
COPY packages/shared ./packages/shared
COPY services/monitoring ./services/monitoring

RUN npm install --workspace=services/monitoring

FROM node:20-alpine
WORKDIR /app
COPY --from=base /app .

EXPOSE 3002
CMD ["node", "services/monitoring/src/server.js"]
