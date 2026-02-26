FROM node:20-alpine AS base
WORKDIR /app

COPY package.json ./
COPY packages/shared ./packages/shared
COPY services/notification ./services/notification

RUN npm install --workspace=services/notification

FROM node:20-alpine
WORKDIR /app
COPY --from=base /app .

EXPOSE 3003
CMD ["node", "services/notification/src/server.js"]
