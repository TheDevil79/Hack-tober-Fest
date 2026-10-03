const express = require('express');
const { z } = require('zod');
const { saveAndEnrichScan, getScan, compareScans, latestScans } = require('../services/scans');
const { remediateFinding } = require('../services/remediation');

const router = express.Router();
const findingSchema = z.object({
  id: z.string().optional(),
  category: z.string().optional(),
  name: z.string().min(1),
  status: z.string().optional(),
  severity: z.string().optional(),
  evidence: z.string().optional()
}).passthrough();
const scanSchema = z.object({
  scanId: z.string().optional(),
  target: z.string().url(),
  tls: z.any().optional(),
  technologies: z.array(z.any()).default([]),
  findings: z.array(findingSchema).default([])
}).passthrough();

function validationError(res, error) {
  if (error instanceof z.ZodError) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Request validation failed',
      issues: error.issues
    });
    return true;
  }
  return false;
}

router.post('/scans', async (req, res, next) => {
  try {
    res.status(201).json(await saveAndEnrichScan(scanSchema.parse(req.body)));
  } catch (error) {
    if (!validationError(res, error)) next(error);
  }
});

router.get('/scans/:id', async (req, res, next) => {
  try {
    const scan = await getScan(req.params.id);
    scan ? res.json(scan) : res.status(404).json({ error: 'Scan not found' });
  } catch (error) {
    next(error);
  }
});

router.get('/history', async (req, res, next) => {
  try {
    if (!req.query.target) return res.status(400).json({ error: 'target is required' });
    return res.json(await latestScans(req.query.target, req.query.limit));
  } catch (error) {
    return next(error);
  }
});

router.post('/compare', async (req, res, next) => {
  try {
    const input = z.object({
      currentId: z.string().min(1),
      previousId: z.string().min(1)
    }).parse(req.body);
    const comparison = await compareScans(input.currentId, input.previousId);
    comparison
      ? res.json(comparison)
      : res.status(404).json({ error: 'One or both scans not found' });
  } catch (error) {
    if (!validationError(res, error)) next(error);
  }
});

router.post('/remediate', async (req, res, next) => {
  try {
    const input = z.object({
      finding: findingSchema,
      technologies: z.array(z.any()).default([])
    }).parse(req.body);
    res.json(await remediateFinding(input.finding, input.technologies));
  } catch (error) {
    if (validationError(res, error)) return;
    if (error.code === 'GEMINI_UNAVAILABLE') {
      return res.status(503).json({
        error: 'Remediation Unavailable',
        message: 'Gemini is not configured'
      });
    }
    return next(error);
  }
});

module.exports = router;
