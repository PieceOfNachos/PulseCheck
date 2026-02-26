const dotenv = require("dotenv");
const path = require("path");

// Load .env from the monorepo root
dotenv.config({ path: path.resolve(__dirname, "../../../.env") });

const config = {
  nodeEnv: process.env.NODE_ENV || "development",
  mongoUri: process.env.MONGO_URI || "mongodb://localhost:27017/pulsecheck",
  redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
  jwtSecret: process.env.JWT_SECRET || "dev-secret-change-me",

  // Service ports
  authPort: parseInt(process.env.AUTH_PORT, 10) || 3001,
  monitoringPort: parseInt(process.env.MONITORING_PORT, 10) || 3002,
  notificationPort: parseInt(process.env.NOTIFICATION_PORT, 10) || 3003,

  // Rate Limiting
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,

  // SMTP
  smtp: {
    host: process.env.SMTP_HOST || "smtp.ethereal.email",
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    user: process.env.SMTP_USER || "",
    pass: process.env.SMTP_PASS || "",
    from: process.env.SMTP_FROM || "noreply@pulsecheck.dev",
  },
};

module.exports = config;
