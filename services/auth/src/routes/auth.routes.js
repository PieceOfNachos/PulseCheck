const authController = require("../controllers/auth.controller");

async function authRoutes(fastify) {
  // POST /api/auth/register
  fastify.post("/register", {
    schema: {
      description: "Create a new user account",
      tags: ["Auth"],
      body: {
        type: "object",
        required: ["email", "password"],
        properties: {
          email: { type: "string", format: "email", description: "User email" },
          password: {
            type: "string",
            minLength: 6,
            description: "Minimum 6 characters",
          },
        },
      },
      response: {
        201: {
          type: "object",
          properties: {
            user: {
              type: "object",
              properties: {
                _id: { type: "string" },
                email: { type: "string" },
                createdAt: { type: "string" },
              },
            },
            token: { type: "string", description: "JWT token" },
          },
        },
        409: {
          type: "object",
          properties: { error: { type: "string" } },
        },
      },
    },
    handler: authController.register,
  });

  // POST /api/auth/login
  fastify.post("/login", {
    schema: {
      description: "Login with email and password, returns JWT",
      tags: ["Auth"],
      body: {
        type: "object",
        required: ["email", "password"],
        properties: {
          email: { type: "string", format: "email" },
          password: { type: "string" },
        },
      },
      response: {
        200: {
          type: "object",
          properties: {
            user: {
              type: "object",
              properties: {
                _id: { type: "string" },
                email: { type: "string" },
                lastLogin: { type: "string" },
              },
            },
            token: { type: "string" },
          },
        },
        401: {
          type: "object",
          properties: { error: { type: "string" } },
        },
      },
    },
    handler: authController.login,
  });

  // GET /api/auth/me  (protected)
  fastify.get("/me", {
    schema: {
      description: "Get the currently authenticated user",
      tags: ["Auth"],
      security: [{ BearerAuth: [] }],
      response: {
        200: {
          type: "object",
          properties: {
            user: {
              type: "object",
              properties: {
                _id: { type: "string" },
                email: { type: "string" },
                lastLogin: { type: "string" },
                createdAt: { type: "string" },
              },
            },
          },
        },
        401: {
          type: "object",
          properties: { error: { type: "string" } },
        },
      },
    },
    preHandler: [fastify.authenticate],
    handler: authController.getMe,
  });
}

module.exports = authRoutes;
