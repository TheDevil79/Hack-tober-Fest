/**
 * Express Application Setup
 * Configures Helmet, CORS, Rate Limiting, Logging, and API Routing.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const scanRoutes = require('./routes/scanRoutes');
const intelligenceRoutes = require('./routes/intelligence');
const authRoutes = require('./routes/auth');
const { requireAuth } = require('./security/auth');
const { logger } = require('./logging/logger');

const app = express();

// Render and similar hosts terminate HTTPS at a trusted reverse proxy.
if (process.env.RENDER || process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// 1. Security Headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false
}));

// 2. CORS Policy
const allowedOrigins = process.env.ALLOWED_ORIGINS || '*';
app.use(cors({
  origin: allowedOrigins === '*' ? '*' : allowedOrigins.split(',').map(o => o.trim()),
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Request Body Parsing (Bounded Size)
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// 4. Rate Limiter for Scan API
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60, // Limit each IP to 60 scan requests per window
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('rate_limit_exceeded', {
      ip: req.ip,
      path: req.originalUrl
    });
    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Scan request limit exceeded. Please try again later.'
    });
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({
    error: 'Too Many Requests',
    message: 'Too many account attempts. Please try again later.'
  })
});

// 5. Request Logging Middleware (Sanitized)
app.use((req, res, next) => {
  if (req.path !== '/api/health') {
    logger.info('http_request_received', {
      method: req.method,
      path: req.path,
      ip: req.ip
    });
  }
  next();
});

// 6. Mount API Routes
app.use('/api/auth', authLimiter);
app.use('/api/auth', authRoutes);
app.use('/api/scan', requireAuth, scanLimiter);
app.use('/api/intelligence', requireAuth);
app.use('/api/intelligence/remediate', scanLimiter);
app.use('/api', scanRoutes);
app.use('/api/intelligence', intelligenceRoutes);

// Compatibility health endpoint used by deployment platforms.
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    service: 'PatchLens Scanner Backend'
  });
});

// Serve the optional production frontend build from the same backend process.
const clientDist = path.resolve(__dirname, '..', '..', 'client', 'dist');
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    return res.sendFile(path.join(clientDist, 'index.html'));
  });
}

// 7. 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.path}`
  });
});

// 8. Global Error Handler (Redacted Stack Traces)
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  logger.error('unhandled_express_error', {
    message: err.message,
    status: err.status || 500
  });

  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message: 'An unexpected server error occurred.'
  });
});

module.exports = app;
