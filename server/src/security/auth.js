const crypto = require('crypto');

const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;

function getConfig() {
  const ttl = Number.parseInt(process.env.AUTH_SESSION_TTL_SECONDS, 10);
  return {
    username: process.env.AUTH_USERNAME || '',
    password: process.env.AUTH_PASSWORD || '',
    secret: process.env.AUTH_SECRET || '',
    ttlSeconds: Number.isFinite(ttl) && ttl >= 300 ? ttl : DEFAULT_SESSION_TTL_SECONDS
  };
}

function hasSigningSecret() {
  return getConfig().secret.length >= 32;
}

function isConfigured() {
  const config = getConfig();
  return hasSigningSecret() && Boolean(
    process.env.MONGODB_URI || (config.username && config.password)
  );
}

function fixedLengthDigest(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function safeEqual(left, right) {
  return crypto.timingSafeEqual(fixedLengthDigest(left), fixedLengthDigest(right));
}

function authenticateCredentials(username, password) {
  const config = getConfig();
  if (!hasSigningSecret() || !config.username || !config.password) return false;
  return safeEqual(username, config.username) && safeEqual(password, config.password);
}

function signPayload(encodedPayload, secret) {
  return crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url');
}

function issueToken(user) {
  const config = getConfig();
  if (!hasSigningSecret()) throw new Error('Authentication signing secret is not configured');

  const account = typeof user === 'string' ? { username: user } : user;
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({
    sub: account.username,
    email: account.email || undefined,
    displayName: account.displayName || undefined,
    iat: now,
    exp: now + config.ttlSeconds
  })).toString('base64url');

  return {
    token: `${payload}.${signPayload(payload, config.secret)}`,
    expiresIn: config.ttlSeconds
  };
}

function verifyToken(token) {
  const config = getConfig();
  if (!hasSigningSecret() || typeof token !== 'string') return null;

  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra) return null;

  const expectedSignature = signPayload(payload, config.secret);
  if (!safeEqual(signature, expectedSignature)) return null;

  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.sub !== 'string' || !claims.sub || !Number.isFinite(claims.exp) || claims.exp <= now) return null;
    return claims;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  if (!isConfigured()) {
    return res.status(503).json({
      error: 'Authentication Unavailable',
      message: 'Authentication has not been configured on the server.'
    });
  }

  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  const claims = match ? verifyToken(match[1]) : null;

  if (!claims) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'A valid login session is required.'
    });
  }

  req.user = {
    username: claims.sub,
    email: claims.email,
    displayName: claims.displayName
  };
  return next();
}

module.exports = {
  authenticateCredentials,
  getConfig,
  hasSigningSecret,
  isConfigured,
  issueToken,
  requireAuth,
  verifyToken
};
