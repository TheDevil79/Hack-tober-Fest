const { ObjectId } = require('mongodb');
const { tryGetDb } = require('../db/mongo');
const { remediateFinding } = require('./remediation');
const { logger } = require('../logging/logger');

const memoryScans = new Map();
const MAX_MEMORY_SCANS = 100;

function publicScan(doc) {
  if (!doc) return null;
  const { _id, ...scan } = doc;
  return { ...scan, scanId: scan.scanId || (_id ? _id.toString() : undefined) };
}

function remember(doc) {
  memoryScans.set(doc.scanId, doc);
  while (memoryScans.size > MAX_MEMORY_SCANS) {
    memoryScans.delete(memoryScans.keys().next().value);
  }
}

function safeAiError(error) {
  if (error && error.code === 'GEMINI_UNAVAILABLE') return 'Gemini is not configured';
  return 'AI remediation is temporarily unavailable';
}

async function enrichFinding(finding, technologies) {
  try {
    const remediation = await remediateFinding(finding, technologies);
    return { ...finding, remediation };
  } catch (error) {
    logger.warn('finding_remediation_unavailable', {
      findingId: finding.id,
      message: error.message
    });
    return {
      ...finding,
      remediation: null,
      remediationUnavailable: true,
      aiError: safeAiError(error)
    };
  }
}

async function saveAndEnrichScan(scan) {
  const technologies = scan.technologies || [];
  const enriched = [];
  const concurrency = Math.max(1, parseInt(process.env.MAX_AI_CONCURRENCY, 10) || 2);
  const findings = scan.findings || [];
  const baseDoc = {
    ...scan,
    scanId: scan.scanId || `scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    findings,
    createdAt: scan.createdAt ? new Date(scan.createdAt) : new Date(),
    intelligenceStatus: 'processing'
  };
  const db = await tryGetDb();
  let persistence = { available: false, storage: 'memory' };

  remember(baseDoc);
  if (db) {
    try {
      await db.collection('scans').updateOne(
        { scanId: baseDoc.scanId },
        { $set: baseDoc },
        { upsert: true }
      );
      persistence = { available: true, storage: 'mongodb' };
    } catch (error) {
      logger.error('initial_scan_persistence_failed', { scanId: baseDoc.scanId, message: error.message });
    }
  }

  for (let index = 0; index < findings.length; index += concurrency) {
    const batch = findings.slice(index, index + concurrency);
    enriched.push(...await Promise.all(batch.map(finding => enrichFinding(finding, technologies))));
  }

  const doc = {
    ...baseDoc,
    findings: enriched,
    intelligenceStatus: 'complete',
    enrichedAt: new Date()
  };

  if (db) {
    try {
      await db.collection('scans').updateOne(
        { scanId: doc.scanId },
        { $set: doc },
        { upsert: true }
      );
      persistence = { available: true, storage: 'mongodb' };
    } catch (error) {
      logger.error('scan_persistence_failed', { scanId: doc.scanId, message: error.message });
      persistence = { available: false, storage: 'memory' };
    }
  }

  remember(doc);
  logger.info('scan_enrichment_completed', {
    scanId: doc.scanId,
    findingsCount: enriched.length,
    persistence: persistence.storage
  });
  return { ...publicScan(doc), persistence };
}

async function getScan(id) {
  const db = await tryGetDb();
  if (db) {
    const filters = [{ scanId: id }];
    if (ObjectId.isValid(id)) filters.push({ _id: new ObjectId(id) });
    try {
      const doc = await db.collection('scans').findOne({ $or: filters });
      if (doc) return publicScan(doc);
    } catch (error) {
      logger.warn('scan_lookup_failed', { scanId: id, message: error.message });
    }
  }
  return publicScan(memoryScans.get(id));
}

function keyOf(f) { return f.id || `${f.category || "finding"}:${f.name}`; }

const RESOLVED_STATUSES = new Set(['present', 'fixed', 'pass', 'secure', 'valid']);

function isResolved(finding) {
  return RESOLVED_STATUSES.has(String(finding && finding.status || '').toLowerCase());
}

async function compareScans(currentId, previousId) {
  const current = await getScan(currentId);
  const previous = await getScan(previousId);
  if (!current || !previous) return null;

  const cur = new Map((current.findings || []).map(f => [keyOf(f), f]));
  const prev = new Map((previous.findings || []).map(f => [keyOf(f), f]));
  const fixed = [], unchanged = [], newIssues = [];

  for (const [key, oldFinding] of prev) {
    const now = cur.get(key);
    if ((!now && !isResolved(oldFinding)) || (now && !isResolved(oldFinding) && isResolved(now))) fixed.push(oldFinding.name);
    else unchanged.push(oldFinding.name);
  }
  for (const [key, now] of cur) {
    const oldFinding = prev.get(key);
    if ((!oldFinding && !isResolved(now)) || (oldFinding && isResolved(oldFinding) && !isResolved(now))) {
      newIssues.push(now.name);
    }
  }

  return { currentId, previousId, fixed, unchanged, newIssues };
}

async function latestScans(target, limit = 10) {
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 10, 1), 100);
  const db = await tryGetDb();
  if (db) {
    try {
      const docs = await db.collection('scans').find({ target }).sort({ createdAt: -1 }).limit(safeLimit)
        .project({ scanId: 1, target: 1, createdAt: 1, timestamp: 1, findings: 1 }).toArray();
      return docs.map(publicScan);
    } catch (error) {
      logger.warn('scan_history_failed', { target, message: error.message });
    }
  }

  return Array.from(memoryScans.values())
    .filter(scan => scan.target === target)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, safeLimit)
    .map(publicScan);
}

module.exports = {
  saveAndEnrichScan,
  getScan,
  compareScans,
  latestScans
};
