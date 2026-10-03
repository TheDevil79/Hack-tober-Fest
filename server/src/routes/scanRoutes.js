/**
 * Scan Routes for PatchLens API
 * Endpoints:
 *   - POST /api/scan
 *   - GET  /api/health
 */

const express = require('express');
const scanner = require('../scanners/scanOrchestrator');
const intelligence = require('../services/scans');
const { logger } = require('../logging/logger');

function createScanRouter({
  executeScan = scanner.executeScan,
  saveAndEnrichScan = intelligence.saveAndEnrichScan
} = {}) {
  const router = express.Router();

  router.get('/health', (req, res) => {
    res.status(200).json({
      status: 'UP',
      service: 'PatchLens Scanner Backend'
    });
  });

  router.post('/scan', async (req, res) => {
    const body = req.body || {};
    const target = body.url || body.target;

    if (!target || typeof target !== 'string' || target.trim().length === 0) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'A valid "url" or "target" URL string is required in the request body.'
      });
    }

    try {
      const scanResult = await executeScan(target.trim());
      const enrichedResult = await saveAndEnrichScan(scanResult);
      return res.status(200).json(enrichedResult);
    } catch (error) {
      const statusCode = error.statusCode || 500;

      if (error.code === 'SSRF_BLOCKED' || statusCode === 400) {
        return res.status(400).json({
          error: 'Invalid Target',
          message: error.message
        });
      }

      logger.error('unhandled_scan_route_error', {
        error: error.message,
        target
      });

      return res.status(500).json({
        error: 'Scan Execution Failed',
        message: 'An internal error occurred during scan execution. Detailed logs are recorded.'
      });
    }
  });

  return router;
}

const router = createScanRouter();
module.exports = router;
module.exports.createScanRouter = createScanRouter;
