const Fastify = require("fastify");
const cors = require("@fastify/cors");
const rateLimit = require("@fastify/rate-limit");
const swagger = require("@fastify/swagger");
const swaggerUi = require("@fastify/swagger-ui");
const {
  config,
  connectMongo,
  authPlugin,
  errorHandler,
} = require("@pulsecheck/shared");
const authRoutes = require("./routes/auth.routes");

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
        title: "PulseCheck — Auth Service",
        description: "Handles user registration, login, and JWT tokens.",
        version: "1.0.0",
      },
      servers: [{ url: `http://localhost:${config.authPort}` }],
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
  await fastify.register(authRoutes, { prefix: "/api/auth" });

  // ── Health check ──
  fastify.get("/health", async () => ({ status: "ok", service: "auth" }));

  return fastify;
}

async function start() {
  try {
    await connectMongo();
    const fastify = await buildServer();
    await fastify.listen({ port: config.authPort, host: "0.0.0.0" });
    console.log(`[Auth Service] Listening on port ${config.authPort}`);
    console.log(`[Auth Service] Rate Limit Max: ${config.rateLimitMax}`);
    console.log(
      `[Auth Service] Swagger docs at http://localhost:${config.authPort}/docs`,
    );
  } catch (err) {
    console.error("[Auth Service] Failed to start:", err);
    process.exit(1);
  }
}

start();

module.exports = { buildServer };
