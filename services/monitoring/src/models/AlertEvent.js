const mongoose = require("mongoose");

const alertEventSchema = new mongoose.Schema({
  monitorId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true,
  },
  type: {
    type: String,
    enum: ["DOWN", "RECOVERED"],
    required: true,
  },
  triggeredAt: {
    type: Date,
    default: Date.now,
  },
  resolvedAt: {
    type: Date,
    default: null,
  },
});

alertEventSchema.set("toJSON", {
  transform(doc, ret) {
    delete ret.__v;
    return ret;
  },
});

const AlertEvent = mongoose.model("AlertEvent", alertEventSchema);

module.exports = AlertEvent;
