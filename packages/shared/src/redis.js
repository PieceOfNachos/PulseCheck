const Redis = require("ioredis");
const config = require("./config");

/**
 * Create a new Redis client instance.
 * @param {string} [url] — override URL, defaults to config.redisUrl
 */
function createRedisClient(url) {
  const client = new Redis(url || config.redisUrl, {
    retryStrategy(times) {
      const delay = Math.min(times * 200, 5000);
      return delay;
    },
    maxRetriesPerRequest: null,
  });

  client.on("connect", () => console.log("[Redis] Connected"));
  client.on("error", (err) => console.error("[Redis] Error:", err.message));

  return client;
}

/**
 * Publish a message to a Redis channel.
 * @param {Redis} client — ioredis instance
 * @param {string} channel
 * @param {object} data — will be JSON.stringified
 */
async function publish(client, channel, data) {
  await client.publish(channel, JSON.stringify(data));
}

/**
 * Subscribe to a Redis channel and call handler on each message.
 * @param {Redis} client — ioredis instance (must be a separate client from publisher)
 * @param {string} channel
 * @param {function} handler — receives parsed JSON data
 */
async function subscribe(client, channel, handler) {
  await client.subscribe(channel);
  client.on("message", (ch, message) => {
    if (ch === channel) {
      try {
        const data = JSON.parse(message);
        handler(data);
      } catch (err) {
        console.error("[Redis] Failed to parse message:", err.message);
      }
    }
  });
  console.log(`[Redis] Subscribed to channel: ${channel}`);
}

module.exports = { createRedisClient, publish, subscribe };
