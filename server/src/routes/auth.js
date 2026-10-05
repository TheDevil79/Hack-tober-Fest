const express = require('express');
const { z } = require('zod');
const { getDb } = require('../db/mongo');
const {
  authenticateCredentials,
  getConfig,
  hasSigningSecret,
  issueToken,
  requireAuth
} = require('../security/auth');
const { hashPassword, verifyPassword } = require('../security/passwords');

const router = express.Router();

const usernameSchema = z.string()
  .trim()
  .min(3, 'Username must contain at least 3 characters.')
  .max(32, 'Username must contain at most 32 characters.')
  .regex(/^[a-zA-Z0-9._-]+$/, 'Username can use letters, numbers, dots, underscores, and hyphens only.');

const signupSchema = z.object({
  displayName: z.string().trim().min(2).max(60),
  username: usernameSchema,
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string()
    .min(10, 'Password must contain at least 10 characters.')
    .max(128)
    .regex(/[a-z]/, 'Password must include a lowercase letter.')
    .regex(/[A-Z]/, 'Password must include an uppercase letter.')
    .regex(/[0-9]/, 'Password must include a number.')
});

const loginSchema = z.object({
  identifier: z.string().trim().min(1).max(254).optional(),
  username: z.string().trim().min(1).max(254).optional(),
  password: z.string().min(1).max(128)
}).refine(input => input.identifier || input.username, {
  message: 'Username or email is required.'
});

function publicUser(user) {
  return {
    username: user.username,
    email: user.email,
    displayName: user.displayName || user.username
  };
}

function sessionResponse(user) {
  return { ...issueToken(user), user: publicUser(user) };
}

function validationError(res, error) {
  if (!(error instanceof z.ZodError)) return false;
  res.status(400).json({
    error: 'Invalid account details',
    message: error.issues[0]?.message || 'Please check the form and try again.',
    issues: error.issues
  });
  return true;
}

router.post('/signup', async (req, res, next) => {
  try {
    if (!hasSigningSecret()) {
      return res.status(503).json({
        error: 'Authentication Unavailable',
        message: 'Account registration has not been configured on the server.'
      });
    }

    const input = signupSchema.parse(req.body || {});
    const db = await getDb();
    const users = db.collection('users');
    const usernameKey = input.username.toLowerCase();
    const emailKey = input.email.toLowerCase();
    const existing = await users.findOne({ $or: [{ usernameKey }, { emailKey }] });
    if (existing) {
      return res.status(409).json({
        error: 'Account already exists',
        message: 'That username or email is already registered.'
      });
    }

    const user = {
      displayName: input.displayName,
      username: input.username,
      usernameKey,
      email: input.email,
      emailKey,
      passwordHash: await hashPassword(input.password),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    try {
      await users.insertOne(user);
    } catch (error) {
      if (error && error.code === 11000) {
        return res.status(409).json({
          error: 'Account already exists',
          message: 'That username or email is already registered.'
        });
      }
      throw error;
    }

    res.set('Cache-Control', 'no-store');
    return res.status(201).json(sessionResponse(user));
  } catch (error) {
    if (validationError(res, error)) return;
    if (error && error.code === 'MONGODB_UNAVAILABLE') {
      return res.status(503).json({
        error: 'Account service unavailable',
        message: 'Account registration is temporarily unavailable. Please try again shortly.'
      });
    }
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    if (!hasSigningSecret()) {
      return res.status(503).json({
        error: 'Authentication Unavailable',
        message: 'Authentication has not been configured on the server.'
      });
    }

    const input = loginSchema.parse(req.body || {});
    const identifier = (input.identifier || input.username).trim();

    if (authenticateCredentials(identifier, input.password)) {
      const admin = { username: getConfig().username, displayName: 'Administrator' };
      res.set('Cache-Control', 'no-store');
      return res.status(200).json(sessionResponse(admin));
    }

    const key = identifier.toLowerCase();
    let db;
    try {
      db = await getDb();
    } catch (error) {
      if (getConfig().username && getConfig().password) {
        return res.status(401).json({
          error: 'Invalid Credentials',
          message: 'The username, email, or password is incorrect.'
        });
      }
      throw error;
    }

    const user = await db.collection('users').findOne({
      $or: [{ usernameKey: key }, { emailKey: key }]
    });
    if (!user || !(await verifyPassword(input.password, user.passwordHash))) {
      return res.status(401).json({
        error: 'Invalid Credentials',
        message: 'The username, email, or password is incorrect.'
      });
    }

    res.set('Cache-Control', 'no-store');
    return res.status(200).json(sessionResponse(user));
  } catch (error) {
    if (validationError(res, error)) return;
    if (error && error.code === 'MONGODB_UNAVAILABLE') {
      return res.status(503).json({
        error: 'Account service unavailable',
        message: 'Sign in is temporarily unavailable. Please try again shortly.'
      });
    }
    return next(error);
  }
});

router.get('/session', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  return res.status(200).json({
    authenticated: true,
    user: req.user,
    expiresIn: getConfig().ttlSeconds
  });
});

module.exports = router;
