const notificationController = require("../controllers/notification.controller");

async function notificationRoutes(fastify) {
  // All routes require authentication
  fastify.addHook("preHandler", fastify.authenticate);

  // GET /api/notifications
  fastify.get("/", {
    schema: {
      description:
        "Get paginated notification history for the authenticated user",
      tags: ["Notifications"],
      security: [{ BearerAuth: [] }],
      querystring: {
        type: "object",
        properties: {
          limit: {
            type: "number",
            default: 50,
            maximum: 100,
            description: "Results per page",
          },
          page: { type: "number", default: 1, description: "Page number" },
        },
      },
      response: {
        200: {
          type: "object",
          properties: {
            notifications: {
              type: "array",
              items: { type: "object", additionalProperties: true },
            },
            pagination: {
              type: "object",
              properties: {
                page: { type: "number" },
                limit: { type: "number" },
                total: { type: "number" },
                pages: { type: "number" },
              },
            },
          },
        },
      },
    },
    handler: notificationController.list,
  });
}

module.exports = notificationRoutes;
