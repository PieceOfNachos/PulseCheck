const NotificationLog = require("../models/NotificationLog");

/**
 * GET /api/notifications
 * Query params: limit, page
 */
async function list(request, reply) {
  const { limit = 50, page = 1 } = request.query;
  const parsedLimit = Math.min(parseInt(limit, 10), 100);
  const skip = (parseInt(page, 10) - 1) * parsedLimit;

  const [notifications, total] = await Promise.all([
    NotificationLog.find({ userId: request.user.id })
      .sort({ sentAt: -1 })
      .skip(skip)
      .limit(parsedLimit),
    NotificationLog.countDocuments({ userId: request.user.id }),
  ]);

  return reply.code(200).send({
    notifications,
    pagination: {
      page: parseInt(page, 10),
      limit: parsedLimit,
      total,
      pages: Math.ceil(total / parsedLimit),
    },
  });
}

module.exports = { list };
