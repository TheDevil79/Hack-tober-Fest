/**
 * Scan Orchestrator
 * Coordinates defensive scanning modules (SSRF, TLS, Headers, Tech, OSV)
 * Implements bounded concurrency, timeout handling, and partial failure resilience.
 */

const { validateTargetUrl } = require('../security/urlPolicy');
const { safeFetch } = require('../utils/httpClient');
const { scanTls } = require('./tlsScanner');
const { scanHeaders } = require('./headerScanner');
const { scanTechnologies } = require('./techScanner');
const { scanAdvisories } = require('./advisoryScanner');
const { logger } = require('../logging/logger');

// Scan concurrency semaphore
const MAX_CONCURRENCY = parseInt(process.env.MAX_SCAN_CONCURRENCY, 10) || 5;
let activeScansCount = 0;
const waitingQueue = [];

function acquireScanSlot() {
  return new Promise((resolve) => {
    if (activeScansCount < MAX_CONCURRENCY) {
      activeScansCount++;
      resolve();
    } else {
      waitingQueue.push(resolve);
    }
  });
}

function releaseScanSlot() {
  activeScansCount--;
  if (waitingQueue.length > 0) {
    activeScansCount++;
    const nextResolve = waitingQueue.shift();
    nextResolve();
  }
}

/**
 * Generates an incremental / random scan ID.
 */
function generateScanId() {
  return `scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
}

/**
 * Executes a full security scan on an authorized target URL.
 *
 * @param {string} targetUrl - URL to scan
 * @param {Object} [options] - Options (timeoutMs, scanId)
 * @returns {Promise<Object>} Standardized scan result matching contract
 */
async function executeScan(targetUrl, options = {}) {
  const scanId = options.scanId || generateScanId();
  const timestamp = new Date().toISOString();
  const timeoutMs = options.timeoutMs || parseInt(process.env.SCAN_TIMEOUT_MS, 10) || 10000;

  logger.info('scan_requested', { scanId, target: targetUrl });

  // 1. Validate Target & Enforce SSRF Policy
  const policy = await validateTargetUrl(targetUrl);
  if (!policy.isValid) {
    logger.warn('scan_rejected_unsafe_url', { scanId, target: targetUrl, reason: policy.reason });
    const err = new Error(`Target URL validation failed: ${policy.reason}`);
    err.statusCode = 400;
    err.code = 'SSRF_BLOCKED';
    throw err;
  }

  await acquireScanSlot();
  logger.info('scan_started', { scanId, target: targetUrl });

  try {
    const parsedUrl = policy.parsedUrl;
    const isHttps = parsedUrl.protocol === 'https:';
    const findings = [];
    const moduleErrors = [];

    // 2. Execute TLS scan (Independent module)
    let tlsResult = { valid: false, protocol: isHttps ? 'unknown' : 'none' };
    try {
      const tlsScanOutput = await scanTls(parsedUrl, Math.min(timeoutMs, 5000));
      tlsResult = {
        valid: tlsScanOutput.valid,
        protocol: tlsScanOutput.protocol
      };
      if (tlsScanOutput.issuer) tlsResult.issuer = tlsScanOutput.issuer;
      if (tlsScanOutput.validTo) tlsResult.validTo = tlsScanOutput.validTo;

      if (Array.isArray(tlsScanOutput.findings)) {
        findings.push(...tlsScanOutput.findings);
      }
      logger.info('module_completed', { scanId, module: 'tls' });
    } catch (tlsErr) {
      logger.error('module_error', { scanId, module: 'tls', error: tlsErr.message });
      moduleErrors.push({
        module: 'tls',
        status: 'error',
        message: `TLS inspection failed: ${tlsErr.message}`
      });
    }

    // 3. Perform Controlled HTTP Fetch
    let httpResponse = null;
    try {
      httpResponse = await safeFetch(targetUrl, { timeoutMs });
    } catch (fetchErr) {
      logger.error('module_error', { scanId, module: 'http_fetch', error: fetchErr.message });
      moduleErrors.push({
        module: 'http_fetch',
        status: 'error',
        message: `HTTP fetch failed: ${fetchErr.message}`
      });
    }

    // 4. Execute Header Scanner (if HTTP response available)
    if (httpResponse && httpResponse.headers) {
      try {
        const headerFindings = scanHeaders(httpResponse.headers, isHttps);
        findings.push(...headerFindings);
        logger.info('module_completed', { scanId, module: 'headers' });
      } catch (headerErr) {
        logger.error('module_error', { scanId, module: 'headers', error: headerErr.message });
        moduleErrors.push({
          module: 'headers',
          status: 'error',
          message: `Header scanner error: ${headerErr.message}`
        });
      }
    }

    // 5. Execute Passive Technology Scanner (if HTTP response available)
    let detectedTechnologies = [];
    if (httpResponse) {
      try {
        detectedTechnologies = scanTechnologies(httpResponse.headers, httpResponse.body);
        logger.info('module_completed', { scanId, module: 'technology' });
      } catch (techErr) {
        logger.error('module_error', { scanId, module: 'technology', error: techErr.message });
        moduleErrors.push({
          module: 'technology',
          status: 'error',
          message: `Technology scanner error: ${techErr.message}`
        });
      }
    }

    // 6. Execute OSV Advisory Scanner (Strict: Only if component AND version are present)
    if (detectedTechnologies.length > 0) {
      try {
        const advisoryFindings = await scanAdvisories(detectedTechnologies, Math.min(timeoutMs, 5000));
        findings.push(...advisoryFindings);
        logger.info('module_completed', { scanId, module: 'advisories' });
      } catch (advisoryErr) {
        logger.error('module_error', { scanId, module: 'advisories', error: advisoryErr.message });
        moduleErrors.push({
          module: 'advisories',
          status: 'error',
          message: `Advisory scanner error: ${advisoryErr.message}`
        });
      }
    }

    // 7. Format clean response conforming to API contract
    const result = {
      scanId,
      target: targetUrl,
      timestamp,
      tls: tlsResult,
      technologies: detectedTechnologies.map(t => {
        const item = {
          name: t.name,
          confidence: t.confidence
        };
        if (t.version) {
          item.version = t.version;
        }
        return item;
      }),
      findings
    };

    if (moduleErrors.length > 0) {
      result.moduleErrors = moduleErrors;
    }

    logger.info('scan_completed', {
      scanId,
      findingsCount: findings.length,
      technologiesCount: detectedTechnologies.length,
      errorsCount: moduleErrors.length
    });

    return result;
  } finally {
    releaseScanSlot();
  }
}

module.exports = {
  executeScan,
  generateScanId,
  acquireScanSlot,
  releaseScanSlot
};
