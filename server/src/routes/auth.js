const express = require('express');
const {
  authenticateCredentials,
  getConfig,
  isConfigured,
  issueToken,
  requireAuth
} = require('../security/auth');

const router = express.Router();

router.post('/login', (req, res) => {
  if (!isConfigured()) {
    return res.status(503).json({
      error: 'Authentication Unavailable',
      message: 'Server login credentials have not been configured.'
    });
  }

  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Username and password are required.'
    });
  }

  if (!authenticateCredentials(username.trim(), password)) {
    return res.status(401).json({
      error: 'Invalid Credentials',
      message: 'The username or password is incorrect.'
    });
  }

  const session = issueToken(username.trim());
  res.set('Cache-Control', 'no-store');
  return res.status(200).json({
    ...session,
    user: { username: username.trim() }
  });
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
