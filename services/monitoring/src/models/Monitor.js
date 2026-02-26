const mongoose = require("mongoose");

const monitorSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    method: {
      type: String,
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
      type: Number,
      default: 30,
      min: 10,
      max: 3600,
    },
    timeoutMs: {
      type: Number,
      default: 5000,
      min: 1000,
      max: 30000,
    },
    expectedStatusCode: {
      type: Number,
      default: 200,
    },
    region: {
      type: String,
      default: "us-east-1",
    },
    active: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  },
);

// Compound index for finding active monitors to check
monitorSchema.index({ active: 1, userId: 1 });

monitorSchema.set("toJSON", {
  transform(doc, ret) {
    delete ret.__v;
    return ret;
  },
});

const Monitor = mongoose.model("Monitor", monitorSchema);

module.exports = Monitor;
