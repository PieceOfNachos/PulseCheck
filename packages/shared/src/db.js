const mongoose = require("mongoose");
const config = require("./config");

/**
 * Connect to MongoDB with retry logic.
 * @param {string} [uri] — override URI, defaults to config.mongoUri
 */
async function connectMongo(uri) {
  const mongoUri = uri || config.mongoUri;

  mongoose.connection.on("connected", () => {
    console.log(`[MongoDB] Connected to ${mongoUri}`);
  });

  mongoose.connection.on("error", (err) => {
    console.error("[MongoDB] Connection error:", err.message);
  });

  mongoose.connection.on("disconnected", () => {
    console.warn("[MongoDB] Disconnected");
  });

  const MAX_RETRIES = 5;
  let retries = 0;

  while (retries < MAX_RETRIES) {
    try {
      await mongoose.connect(mongoUri);
      return mongoose.connection;
    } catch (err) {
      retries++;
      console.error(
        `[MongoDB] Connection attempt ${retries}/${MAX_RETRIES} failed: ${err.message}`,
      );
      if (retries >= MAX_RETRIES) {
        throw new Error("[MongoDB] Max retries reached. Exiting.");
      }
      // Exponential backoff: 1s, 2s, 4s, 8s, 16s
      await new Promise((resolve) =>
        setTimeout(resolve, Math.pow(2, retries) * 1000),
      );
    }
  }
}

module.exports = { connectMongo };
