const fp = require("fastify-plugin");

/**
 * Global error handler plugin.
 * Catches all errors and returns a consistent JSON response.
 */
async function errorHandler(fastify) {
  fastify.setErrorHandler((error, request, reply) => {
    const statusCode = error.statusCode || 500;

    request.log.error({
      err: error,
      statusCode,
      url: request.url,
      method: request.method,
    });

    reply.code(statusCode).send({
      error: error.name || "InternalServerError",
      message: error.message || "Something went wrong",
      statusCode,
    });
  });
}

module.exports = fp(errorHandler);
