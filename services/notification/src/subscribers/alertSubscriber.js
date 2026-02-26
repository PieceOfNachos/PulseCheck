const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const { config, subscribe } = require("@pulsecheck/shared");
const NotificationLog = require("../models/NotificationLog");

// User model isn't in this service, so we query the users collection directly
const getUserEmail = async (userId) => {
  const db = mongoose.connection.db;
  const user = await db
    .collection("users")
    .findOne({ _id: new mongoose.Types.ObjectId(userId) });
  return user ? user.email : null;
};

/**
 * Create the SMTP transporter.
 * Uses Ethereal (fake SMTP) in development if no creds are provided.
 */
async function createTransporter() {
  if (config.smtp.user && config.smtp.pass) {
    return nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.port === 465,
      auth: {
        user: config.smtp.user,
        pass: config.smtp.pass,
      },
    });
  }

  // In dev, create an Ethereal test account
  console.log(
    "[Email] No SMTP credentials configured, creating Ethereal test account...",
  );
  const testAccount = await nodemailer.createTestAccount();
  const transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass,
    },
  });
  console.log(`[Email] Ethereal test account: ${testAccount.user}`);
  return transporter;
}

/**
 * Start the Redis subscriber that listens for alert events
 * and sends email notifications.
 *
 * @param {object} redisClient — ioredis subscriber client
 */
async function startAlertSubscriber(redisClient) {
  const transporter = await createTransporter();

  await subscribe(redisClient, "alert:status-change", async (data) => {
    console.log(
      `[Alert Subscriber] Received alert:`,
      data.type,
      data.monitorName,
    );

    let status = "FAILED";
    let errorMessage = null;

    try {
      const userEmail = await getUserEmail(data.userId);
      if (!userEmail) {
        throw new Error(`User not found: ${data.userId}`);
      }

      const subject =
        data.type === "DOWN"
          ? `🔴 ALERT: ${data.monitorName} is DOWN`
          : `🟢 RECOVERED: ${data.monitorName} is back UP`;

      const html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: ${data.type === "DOWN" ? "#e74c3c" : "#27ae60"};">
            ${data.type === "DOWN" ? "🔴 API Down Alert" : "🟢 API Recovered"}
          </h2>
          <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Monitor</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${data.monitorName}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>URL</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${data.monitorUrl}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Status</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${data.type}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Status Code</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${data.statusCode || "N/A"}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Latency</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${data.latencyMs}ms</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Time</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">${data.timestamp}</td></tr>
            ${data.errorMessage ? `<tr><td style="padding: 8px;"><strong>Error</strong></td><td style="padding: 8px;">${data.errorMessage}</td></tr>` : ""}
          </table>
          <p style="margin-top: 20px; color: #888; font-size: 12px;">— PulseCheck Monitoring</p>
        </div>
      `;

      const info = await transporter.sendMail({
        from: config.smtp.from,
        to: userEmail,
        subject,
        html,
      });

      status = "SENT";
      console.log(`[Email] Sent to ${userEmail}: ${subject}`);

      // Log Ethereal preview URL in development
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) {
        console.log(`[Email] Preview URL: ${previewUrl}`);
      }
    } catch (err) {
      errorMessage = err.message;
      console.error(`[Email] Failed to send notification:`, err.message);
    }

    // Log the notification
    await NotificationLog.create({
      userId: data.userId,
      alertEventId: data.alertEventId,
      channel: "EMAIL",
      status,
      errorMessage,
      sentAt: new Date(),
    });
  });
}

module.exports = { startAlertSubscriber };
