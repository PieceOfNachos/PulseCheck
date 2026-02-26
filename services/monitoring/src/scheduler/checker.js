const axios = require("axios");
const Monitor = require("../models/Monitor");
const CheckResult = require("../models/CheckResult");
const AlertEvent = require("../models/AlertEvent");
const { publish } = require("@pulsecheck/shared");

// In-memory map to track last known status per monitor
const lastKnownStatus = new Map();

/**
 * Ping a single monitor endpoint and record the result.
 * If the status changes (UP→DOWN or DOWN→UP), publish an alert to Redis.
 *
 * @param {object} monitor — Mongoose Monitor document
 * @param {object} redisClient — ioredis publisher client
 */
async function pingMonitor(monitor, redisClient) {
  const startTime = Date.now();
  let status = "UP";
  let statusCode = null;
  let errorMessage = null;

  try {
    const response = await axios({
      method: monitor.method.toLowerCase(),
      url: monitor.url,
      timeout: monitor.timeoutMs,
      validateStatus: () => true, // Don't throw on any status code
    });

    statusCode = response.status;

    if (statusCode !== monitor.expectedStatusCode) {
      status = "DOWN";
      errorMessage = `Expected ${monitor.expectedStatusCode}, got ${statusCode}`;
    }
  } catch (err) {
    status = "DOWN";
    errorMessage = err.code || err.message;
  }

  const latencyMs = Date.now() - startTime;

  // Save CheckResult
  await CheckResult.create({
    monitorId: monitor._id,
    status,
    statusCode,
    latencyMs,
    errorMessage,
    region: monitor.region || "us-east-1",
    checkedAt: new Date(),
  });

  // Detect status change
  const previousStatus = lastKnownStatus.get(monitor._id.toString());
  lastKnownStatus.set(monitor._id.toString(), status);

  if (previousStatus && previousStatus !== status) {
    const alertType = status === "DOWN" ? "DOWN" : "RECOVERED";

    // Create AlertEvent
    const alertEvent = await AlertEvent.create({
      monitorId: monitor._id,
      type: alertType,
      triggeredAt: new Date(),
    });

    // If recovered, mark the last DOWN alert as resolved
    if (alertType === "RECOVERED") {
      await AlertEvent.findOneAndUpdate(
        { monitorId: monitor._id, type: "DOWN", resolvedAt: null },
        { resolvedAt: new Date() },
        { sort: { triggeredAt: -1 } },
      );
    }

    // Publish to Redis for the notification service
    await publish(redisClient, "alert:status-change", {
      alertEventId: alertEvent._id,
      monitorId: monitor._id,
      userId: monitor.userId,
      monitorName: monitor.name,
      monitorUrl: monitor.url,
      type: alertType,
      statusCode,
      latencyMs,
      errorMessage,
      timestamp: new Date().toISOString(),
    });

    console.log(
      `[Checker] Alert: ${monitor.name} (${monitor.url}) → ${alertType}`,
    );
  }
}

/**
 * Start the monitoring scheduler.
 * Uses setInterval per monitor; re-syncs the list of active monitors periodically.
 *
 * @param {object} redisClient — ioredis publisher client
 */
function startScheduler(redisClient) {
  const intervals = new Map(); // monitorId → intervalId

  async function syncMonitors() {
    try {
      const activeMonitors = await Monitor.find({ active: true });
      const activeIds = new Set(activeMonitors.map((m) => m._id.toString()));

      // Stop intervals for monitors that are no longer active
      for (const [id, intervalId] of intervals) {
        if (!activeIds.has(id)) {
          clearInterval(intervalId);
          intervals.delete(id);
          lastKnownStatus.delete(id);
          console.log(`[Scheduler] Stopped monitoring: ${id}`);
        }
      }

      // Start intervals for new active monitors
      for (const monitor of activeMonitors) {
        const id = monitor._id.toString();
        if (!intervals.has(id)) {
          console.log(
            `[Scheduler] Starting monitoring: ${monitor.name} (${monitor.url}) every ${monitor.intervalSeconds}s`,
          );

          // Immediate first check
          pingMonitor(monitor, redisClient).catch((err) =>
            console.error(
              `[Checker] Error pinging ${monitor.name}:`,
              err.message,
            ),
          );

          const intervalId = setInterval(() => {
            // Re-fetch the monitor to get latest config
            Monitor.findById(monitor._id)
              .then((freshMonitor) => {
                if (freshMonitor && freshMonitor.active) {
                  pingMonitor(freshMonitor, redisClient).catch((err) =>
                    console.error(
                      `[Checker] Error pinging ${freshMonitor.name}:`,
                      err.message,
                    ),
                  );
                }
              })
              .catch((err) =>
                console.error(
                  `[Scheduler] Error fetching monitor:`,
                  err.message,
                ),
              );
          }, monitor.intervalSeconds * 1000);

          intervals.set(id, intervalId);
        }
      }
    } catch (err) {
      console.error("[Scheduler] Sync error:", err.message);
    }
  }

  // Initial sync
  syncMonitors();

  // Re-sync every 30 seconds to pick up new/removed monitors
  setInterval(syncMonitors, 30000);

  console.log("[Scheduler] Monitor scheduler started");
}

module.exports = { startScheduler, pingMonitor };
