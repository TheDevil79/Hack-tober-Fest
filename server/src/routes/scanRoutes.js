/**
 * Scan Routes for PatchLens API
 * Endpoints:
 *   - POST /api/scan
 *   - GET  /api/health
 */

const express = require('express');
const { executeScan } = require('../scanners/scanOrchestrator');
const { logger } = require('../logging/logger');

const router = express.Router();

/**
 * GET /api/health
 * Health check endpoint for container / orchestrator probes.
 */
router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    service: 'PatchLens Scanner Backend'
  });
});

/**
 * POST /api/scan
 * Initiates a defensive security scan on an authorized URL target.
 */
router.post('/scan', async (req, res) => {
  const { target } = req.body || {};

  if (!target || typeof target !== 'string' || target.trim().length === 0) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'A valid "target" URL string is required in the request body (e.g. {"target": "https://example.com"}).'
    });
  }

  try {
    const scanResult = await executeScan(target.trim());
    return res.status(200).json(scanResult);
  } catch (err) {
    const statusCode = err.statusCode || 500;

    if (err.code === 'SSRF_BLOCKED' || statusCode === 400) {
      return res.status(400).json({
        error: 'Invalid Target',
        message: err.message
      });
    }

    logger.error('unhandled_scan_route_error', {
      error: err.message,
      target
    });

    return res.status(500).json({
      error: 'Scan Execution Failed',
      message: 'An internal error occurred during scan execution. Detailed logs are recorded.'
    });
  }
});

module.exports = router;
