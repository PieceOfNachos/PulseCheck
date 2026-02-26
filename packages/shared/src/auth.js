const jwt = require("jsonwebtoken");
const fp = require("fastify-plugin");
const config = require("./config");

/**
 * Fastify plugin that adds an `authenticate` preHandler hook.
 * Verifies the JWT from the Authorization header and attaches
 * decoded user data to `request.user`.
 */
async function authPlugin(fastify) {
  fastify.decorate("authenticate", async function (request, reply) {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return reply.code(401).send({ error: "Missing or invalid token" });
    }

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, config.jwtSecret);
      request.user = decoded;
    } catch (err) {
      return reply.code(401).send({ error: "Token expired or invalid" });
    }
  });
}

/**
 * Generate a JWT for a user.
 * @param {object} payload — data to encode (typically { id, email })
 * @param {string} [expiresIn="7d"]
 */
function generateToken(payload, expiresIn = "7d") {
  return jwt.sign(payload, config.jwtSecret, { expiresIn });
}

module.exports = fp(authPlugin);
module.exports.generateToken = generateToken;
