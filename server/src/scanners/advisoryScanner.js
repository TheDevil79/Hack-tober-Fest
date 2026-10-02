/**
 * OSV Vulnerability Advisory Scanner
 * Strictly queries the Open Source Vulnerability (OSV) database ONLY when
 * a component AND an exact reliable version are identified.
 */

const https = require('https');
const http = require('http');
const { normalizeFinding, FINDING_CATEGORIES, SEVERITY_LEVELS } = require('../utils/normalizeFinding');
const { logger } = require('../logging/logger');

const OSV_API_URL = process.env.OSV_BASE_URL || 'https://api.osv.dev/v1/query';

// Mapping known component names to standard OSV ecosystem packages
const KNOWN_ECOSYSTEM_MAP = {
  'express': { name: 'express', ecosystem: 'npm' },
  'react': { name: 'react', ecosystem: 'npm' },
  'vue': { name: 'vue', ecosystem: 'npm' },
  'jquery': { name: 'jquery', ecosystem: 'npm' },
  'bootstrap': { name: 'bootstrap', ecosystem: 'npm' },
  'next.js': { name: 'next', ecosystem: 'npm' },
  'next': { name: 'next', ecosystem: 'npm' },
  'nuxt': { name: 'nuxt', ecosystem: 'npm' },
  'laravel': { name: 'laravel/framework', ecosystem: 'Packagist' },
  'django': { name: 'django', ecosystem: 'PyPI' },
  'flask': { name: 'flask', ecosystem: 'PyPI' },
  'wordpress': { name: 'WordPress', ecosystem: 'WordPress' }
};

/**
 * Sends a query payload to OSV database.
 */
function queryOsvApi(payload, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(OSV_API_URL);
      const transport = url.protocol === 'https:' ? https : http;
      const dataStr = JSON.stringify(payload);

      const req = transport.request({
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(dataStr),
          'User-Agent': 'PatchLens-Security-Scanner/1.0'
        },
        timeout: timeoutMs
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const json = JSON.parse(body);
              resolve(json);
            } catch (parseErr) {
              resolve({ vulns: [] });
            }
          } else {
            resolve({ vulns: [] });
          }
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error(`OSV API request timed out after ${timeoutMs}ms`));
      });

      req.on('error', (err) => {
        logger.warn('osv_query_error', { message: err.message });
        resolve({ vulns: [] }); // defensive fallback
      });

      req.write(dataStr);
      req.end();
    } catch (err) {
      resolve({ vulns: [] });
    }
  });
}

/**
 * Scans identified technologies for known OSV advisories.
 * STRICT RULE: Only query when both name and valid version are present!
 *
 * @param {Array<{name: string, version?: string, confidence: string}>} technologies
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<Array<Object>>} Normalized vulnerability findings
 */
async function scanAdvisories(technologies = [], timeoutMs = 5000) {
  const findings = [];

  for (const tech of technologies) {
    // 1. Guard check: Component name and reliable version MUST both be present
    if (!tech.name || !tech.version || typeof tech.version !== 'string') {
      // Do NOT query OSV or infer any vulnerability without a confirmed version
      continue;
    }

    const lowerName = tech.name.toLowerCase();
    const pkgMapping = KNOWN_ECOSYSTEM_MAP[lowerName];

    const payload = {
      version: tech.version,
      package: pkgMapping ? {
        name: pkgMapping.name,
        ecosystem: pkgMapping.ecosystem
      } : {
        name: tech.name
      }
    };

    try {
      const response = await queryOsvApi(payload, timeoutMs);

      if (response && Array.isArray(response.vulns) && response.vulns.length > 0) {
        for (const vuln of response.vulns) {
          const vulnId = vuln.id || 'OSV-UNKNOWN';
          const summary = vuln.summary || (vuln.details ? vuln.details.substring(0, 120) : 'Security Advisory');

          // Extract CVSS / severity rating
          let severity = SEVERITY_LEVELS.HIGH;
          if (vuln.database_specific && vuln.database_specific.severity) {
            const rawSev = String(vuln.database_specific.severity).toLowerCase();
            if (['critical', 'high', 'medium', 'low'].includes(rawSev)) {
              severity = rawSev;
            }
          }

          findings.push(
            normalizeFinding({
              id: `advisory-${vulnId.toLowerCase()}`,
              category: FINDING_CATEGORIES.VULNERABILITY,
              name: `${tech.name} ${tech.version}: ${vulnId}`,
              status: 'vulnerable',
              severity,
              evidence: `OSV Advisory ${vulnId}: ${summary}`,
              details: {
                technology: tech.name,
                version: tech.version,
                advisoryId: vulnId,
                aliases: vuln.aliases || []
              }
            })
          );
        }
      }
    } catch (err) {
      logger.warn('advisory_scan_failed_for_component', {
        component: tech.name,
        version: tech.version,
        error: err.message
      });
    }
  }

  return findings;
}

module.exports = {
  scanAdvisories,
  queryOsvApi,
  KNOWN_ECOSYSTEM_MAP
};
