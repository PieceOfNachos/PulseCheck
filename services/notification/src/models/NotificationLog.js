const mongoose = require("mongoose");

const notificationLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true,
  },
  alertEventId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  channel: {
    type: String,
    enum: ["EMAIL"],
    default: "EMAIL",
  },
  status: {
    type: String,
    enum: ["SENT", "FAILED"],
    required: true,
  },
  errorMessage: {
    type: String,
    default: null,
  },
  sentAt: {
    type: Date,
    default: Date.now,
  },
});

notificationLogSchema.index({ userId: 1, sentAt: -1 });

notificationLogSchema.set("toJSON", {
  transform(doc, ret) {
    delete ret.__v;
    return ret;
  },
});

const NotificationLog = mongoose.model(
  "NotificationLog",
  notificationLogSchema,
);

module.exports = NotificationLog;
