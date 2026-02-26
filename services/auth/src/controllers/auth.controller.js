const User = require("../models/User");
const { generateToken } = require("@pulsecheck/shared");

/**
 * POST /api/auth/register
 */
async function register(request, reply) {
  const { email, password } = request.body;

  // Check if user already exists
  const existing = await User.findOne({ email });
  if (existing) {
    return reply.code(409).send({ error: "Email already registered" });
  }

  // Hash password and create user
  const passwordHash = await User.hashPassword(password);
  const user = await User.create({ email, passwordHash });

  // Generate token
  const token = generateToken({ id: user._id, email: user.email });

  return reply.code(201).send({
    user: user.toJSON(),
    token,
  });
}

/**
 * POST /api/auth/login
 */
async function login(request, reply) {
  const { email, password } = request.body;

  const user = await User.findOne({ email });
  if (!user) {
    return reply.code(401).send({ error: "Invalid email or password" });
  }

  const isValid = await user.comparePassword(password);
  if (!isValid) {
    return reply.code(401).send({ error: "Invalid email or password" });
  }

  // Update last login
  user.lastLogin = new Date();
  await user.save();

  const token = generateToken({ id: user._id, email: user.email });

  return reply.code(200).send({
    user: user.toJSON(),
    token,
  });
}

/**
 * GET /api/auth/me
 */
async function getMe(request, reply) {
  const user = await User.findById(request.user.id).select("-passwordHash");
  if (!user) {
    return reply.code(404).send({ error: "User not found" });
  }
  return reply.code(200).send({ user: user.toJSON() });
}

module.exports = { register, login, getMe };
