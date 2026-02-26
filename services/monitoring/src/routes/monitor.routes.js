const monitorController = require("../controllers/monitor.controller");

async function monitorRoutes(fastify) {
  // All routes require authentication
  fastify.addHook("preHandler", fastify.authenticate);

  // POST /api/monitors
  fastify.post("/", {
    schema: {
      description: "Create a new monitor to track an API endpoint",
      tags: ["Monitors"],
      security: [{ BearerAuth: [] }],
      body: {
        type: "object",
        required: ["name", "url"],
        properties: {
          name: {
            type: "string",
            minLength: 1,
            description: "Friendly name for this monitor",
          },
          url: {
            type: "string",
            format: "uri",
            description:
              "Full URL to monitor (e.g. https://api.example.com/health)",
          },
          method: {
            type: "string",
            enum: [
              "GET",
              "POST",
              "PUT",
              "PATCH",
              "DELETE",
              "HEAD",
              "OPTIONS",
              "CONNECT",
              "TRACE",
            ],
            default: "GET",
          },
          intervalSeconds: {
            type: "number",
            minimum: 10,
            maximum: 3600,
            default: 30,
            description: "How often to check (seconds)",
          },
          timeoutMs: {
            type: "number",
            minimum: 1000,
            maximum: 30000,
            default: 5000,
            description: "Request timeout (ms)",
          },
          expectedStatusCode: {
            type: "number",
            default: 200,
            description: "HTTP status code that means 'UP'",
          },
        },
      },
      response: {
        201: {
          type: "object",
          properties: {
            monitor: { type: "object" },
          },
        },
      },
    },
    handler: monitorController.create,
  });

  // GET /api/monitors
  fastify.get("/", {
    schema: {
      description: "List all monitors belonging to the authenticated user",
      tags: ["Monitors"],
      security: [{ BearerAuth: [] }],
      response: {
        200: {
          type: "object",
          properties: {
            monitors: { type: "array", items: { type: "object" } },
          },
        },
      },
    },
    handler: monitorController.list,
  });

  // GET /api/monitors/:id
  fastify.get("/:id", {
    schema: {
      description: "Get a single monitor with its last 20 check results",
      tags: ["Monitors"],
      security: [{ BearerAuth: [] }],
      params: {
        type: "object",
        properties: {
          id: { type: "string", description: "Monitor ID" },
        },
      },
    },
    handler: monitorController.getOne,
  });

  // PUT /api/monitors/:id
  fastify.put("/:id", {
    schema: {
      description: "Update an existing monitor's settings",
      tags: ["Monitors"],
      security: [{ BearerAuth: [] }],
      params: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
      },
      body: {
        type: "object",
        properties: {
          name: { type: "string", minLength: 1 },
          url: { type: "string", format: "uri" },
          method: { type: "string" },
          intervalSeconds: { type: "number", minimum: 10, maximum: 3600 },
          timeoutMs: { type: "number", minimum: 1000, maximum: 30000 },
          expectedStatusCode: { type: "number" },
          active: { type: "boolean", description: "Pause/resume monitoring" },
        },
      },
    },
    handler: monitorController.update,
  });

  // DELETE /api/monitors/:id
  fastify.delete("/:id", {
    schema: {
      description: "Delete a monitor and all its check history",
      tags: ["Monitors"],
      security: [{ BearerAuth: [] }],
      params: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
      },
    },
    handler: monitorController.remove,
  });

  // GET /api/monitors/:id/checks
  fastify.get("/:id/checks", {
    schema: {
      description:
        "Get the check result history for a monitor, with optional date filtering",
      tags: ["Check Results"],
      security: [{ BearerAuth: [] }],
      params: {
        type: "object",
        properties: {
          id: { type: "string", description: "Monitor ID" },
        },
      },
      querystring: {
        type: "object",
        properties: {
          dateStart: {
            type: "string",
            format: "date-time",
            description: "Filter from this date (ISO 8601)",
          },
          dateEnd: {
            type: "string",
            format: "date-time",
            description: "Filter until this date (ISO 8601)",
          },
          limit: {
            type: "number",
            default: 100,
            maximum: 500,
            description: "Max results to return",
          },
        },
      },
    },
    handler: monitorController.getChecks,
  });
}

module.exports = monitorRoutes;
