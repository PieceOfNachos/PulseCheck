const Fastify = require("fastify");
const cors = require("@fastify/cors");
const rateLimit = require("@fastify/rate-limit");
const swagger = require("@fastify/swagger");
const swaggerUi = require("@fastify/swagger-ui");
const {
  config,
  connectMongo,
  createRedisClient,
  authPlugin,
  errorHandler,
} = require("@pulsecheck/shared");
const monitorRoutes = require("./routes/monitor.routes");
const { startScheduler } = require("./scheduler/checker");

async function buildServer() {
  const fastify = Fastify({
    logger: config.nodeEnv === "development",
  });

  // ── Plugins ──
  await fastify.register(cors, { origin: true });
  // Disable rate limiting if max is set to -1
  if (config.rateLimitMax !== -1) {
    await fastify.register(rateLimit, {
      max: config.rateLimitMax,
      timeWindow: "1 minute",
    });
  }
  await fastify.register(errorHandler);
  await fastify.register(authPlugin);

  // ── Swagger Docs ──
  await fastify.register(swagger, {
    openapi: {
      info: {
        title: "PulseCheck — Monitoring Service",
        description:
          "Manages monitors, runs periodic health checks, and publishes alerts to Redis.",
        version: "1.0.0",
      },
      servers: [{ url: `http://localhost:${config.monitoringPort}` }],
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
  await fastify.register(monitorRoutes, { prefix: "/api/monitors" });

  // ── Health check ──
  fastify.get("/health", async () => ({
    status: "ok",
    service: "monitoring",
  }));

  return fastify;
}

async function start() {
  try {
    await connectMongo();

    // Create Redis client for publishing alerts
    const redisClient = createRedisClient();

    const fastify = await buildServer();
    await fastify.listen({ port: config.monitoringPort, host: "0.0.0.0" });
    console.log(
      `[Monitoring Service] Listening on port ${config.monitoringPort}`,
    );
    console.log(`[Monitoring Service] Rate Limit Max: ${config.rateLimitMax}`);
    console.log(
      `[Monitoring Service] Swagger docs at http://localhost:${config.monitoringPort}/docs`,
    );

    // Start the background scheduler
    startScheduler(redisClient);
  } catch (err) {
    console.error("[Monitoring Service] Failed to start:", err);
    process.exit(1);
  }
}

start();

module.exports = { buildServer };
