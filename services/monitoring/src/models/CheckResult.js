const mongoose = require("mongoose");

const checkResultSchema = new mongoose.Schema({
  monitorId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true,
  },
  status: {
    type: String,
    enum: ["UP", "DOWN"],
    required: true,
  },
  statusCode: {
    type: Number,
    default: null,
  },
  latencyMs: {
    type: Number,
    default: null,
  },
  errorMessage: {
    type: String,
    default: null,
  },
  region: {
    type: String,
    default: "us-east-1",
  },
  checkedAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for time-range queries on check history
checkResultSchema.index({ monitorId: 1, checkedAt: -1 });

checkResultSchema.set("toJSON", {
  transform(doc, ret) {
    delete ret.__v;
    return ret;
  },
});

const CheckResult = mongoose.model("CheckResult", checkResultSchema);

module.exports = CheckResult;
