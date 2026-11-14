const Fastify = require("fastify");
const cors = require("@fastify/cors");
const swagger = require("@fastify/swagger");
const swaggerUi = require("@fastify/swagger-ui");
const {
  config,
  connectMongo,
  createRedisClient,
  authPlugin,
  errorHandler,
} = require("@pulsecheck/shared");
const notificationRoutes = require("./routes/notification.routes");
const { startAlertSubscriber } = require("./subscribers/alertSubscriber");

async function buildServer() {
  const fastify = Fastify({
    logger: config.nodeEnv === "development",
  });

  // ── Plugins ──
  await fastify.register(cors, {
    origin: true,
    methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
  });
  await fastify.register(errorHandler);
  await fastify.register(authPlugin);

  // ── Swagger Docs ──
  await fastify.register(swagger, {
    openapi: {
      info: {
        title: "PulseCheck — Notification Service",
        description:
          "Listens for alerts via Redis, sends emails, and logs notification history.",
        version: "1.0.0",
      },
      servers: [{ url: `http://localhost:${config.notificationPort}` }],
      components: {
        securitySchemes: {
          BearerAuth: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
          },
        },
      },
    },
  });
  await fastify.register(swaggerUi, {
    routePrefix: "/docs",
  });

  // ── Routes ──
  await fastify.register(notificationRoutes, {
    prefix: "/api/notifications",
  });

  // ── Health check ──
  fastify.get("/health", async () => ({
    status: "ok",
    service: "notification",
  }));

  return fastify;
}

async function start() {
  try {
    await connectMongo();

    // Create a SEPARATE Redis client for subscribing (ioredis requirement)
    const redisSubscriber = createRedisClient();

    // Start listening for alert events
    await startAlertSubscriber(redisSubscriber);

    const fastify = await buildServer();
    await fastify.listen({ port: config.notificationPort, host: "0.0.0.0" });
    console.log(
      `[Notification Service] Listening on port ${config.notificationPort}`,
    );
    console.log(
      `[Notification Service] Swagger docs at http://localhost:${config.notificationPort}/docs`,
    );
  } catch (err) {
    console.error("[Notification Service] Failed to start:", err);
    process.exit(1);
  }
}

start();

module.exports = { buildServer };
