const Monitor = require("../models/Monitor");
const CheckResult = require("../models/CheckResult");

/**
 * POST /api/monitors
 */
async function create(request, reply) {
  const monitor = await Monitor.create({
    ...request.body,
    userId: request.user.id,
  });
  return reply.code(201).send({ monitor });
}

/**
 * GET /api/monitors
 */
async function list(request, reply) {
  const monitors = await Monitor.find({ userId: request.user.id }).sort({
    createdAt: -1,
  });
  return reply.code(200).send({ monitors });
}

/**
 * GET /api/monitors/:id
 */
async function getOne(request, reply) {
  const monitor = await Monitor.findOne({
    _id: request.params.id,
    userId: request.user.id,
  });

  if (!monitor) {
    return reply.code(404).send({ error: "Monitor not found" });
  }

  // Fetch last 20 check results
  const recentChecks = await CheckResult.find({ monitorId: monitor._id })
    .sort({ checkedAt: -1 })
    .limit(20);

  return reply.code(200).send({ monitor, recentChecks });
}

/**
 * PUT /api/monitors/:id
 */
async function update(request, reply) {
  const monitor = await Monitor.findOneAndUpdate(
    { _id: request.params.id, userId: request.user.id },
    { $set: request.body },
    { new: true, runValidators: true },
  );

  if (!monitor) {
    return reply.code(404).send({ error: "Monitor not found" });
  }

  return reply.code(200).send({ monitor });
}

/**
 * DELETE /api/monitors/:id
 */
async function remove(request, reply) {
  const monitor = await Monitor.findOneAndDelete({
    _id: request.params.id,
    userId: request.user.id,
  });

  if (!monitor) {
    return reply.code(404).send({ error: "Monitor not found" });
  }

  // Clean up related check results
  await CheckResult.deleteMany({ monitorId: monitor._id });

  return reply.code(200).send({ message: "Monitor deleted" });
}

/**
 * GET /api/monitors/:id/checks
 * Query params: dateStart, dateEnd, limit
 */
async function getChecks(request, reply) {
  // Verify ownership
  const monitor = await Monitor.findOne({
    _id: request.params.id,
    userId: request.user.id,
  });

  if (!monitor) {
    return reply.code(404).send({ error: "Monitor not found" });
  }

  const { dateStart, dateEnd, limit = 100 } = request.query;

  const filter = { monitorId: monitor._id };
  if (dateStart || dateEnd) {
    filter.checkedAt = {};
    if (dateStart) filter.checkedAt.$gte = new Date(dateStart);
    if (dateEnd) filter.checkedAt.$lte = new Date(dateEnd);
  }

  const checks = await CheckResult.find(filter)
    .sort({ checkedAt: -1 })
    .limit(Math.min(parseInt(limit, 10), 500));

  return reply.code(200).send({ checks });
}

module.exports = { create, list, getOne, update, remove, getChecks };
