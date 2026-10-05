/**
 * HTTP Security Headers Scanner
 * Deterministically evaluates response headers for presence and recommended security policies.
 */

const { normalizeFinding, FINDING_CATEGORIES, SEVERITY_LEVELS } = require('../utils/normalizeFinding');

const REQUIRED_HEADERS = [
  {
    id: 'header-csp',
    headerName: 'content-security-policy',
    displayName: 'Content-Security-Policy',
    severity: SEVERITY_LEVELS.HIGH,
    validate: (val) => {
      if (!val) return { status: 'missing', evidence: 'Header not observed in response' };
      return { status: 'present', evidence: `Configured: ${val.substring(0, 150)}${val.length > 150 ? '...' : ''}` };
    }
  },
  {
    id: 'header-hsts',
    headerName: 'strict-transport-security',
    displayName: 'Strict-Transport-Security',
    severity: SEVERITY_LEVELS.MEDIUM,
    requiresHttps: true,
    validate: (val, isHttps) => {
      if (!isHttps) {
        return null; // HSTS is only applicable on HTTPS
      }
      if (!val) {
        return { status: 'missing', evidence: 'Strict-Transport-Security header not observed on HTTPS response' };
      }
      return { status: 'present', evidence: `Configured: ${val}` };
    }
  },
  {
    id: 'header-x-content-type-options',
    headerName: 'x-content-type-options',
    displayName: 'X-Content-Type-Options',
    severity: SEVERITY_LEVELS.MEDIUM,
    validate: (val) => {
      if (!val) {
        return { status: 'missing', evidence: 'Header not observed in response' };
      }
      if (val.toLowerCase().trim() !== 'nosniff') {
        return {
          status: 'warning',
          evidence: `Value '${val}' does not match the recommended 'nosniff'`
        };
      }
      return { status: 'present', evidence: `Configured with value '${val}'` };
    }
  },
  {
    id: 'header-x-frame-options',
    headerName: 'x-frame-options',
    displayName: 'X-Frame-Options',
    severity: SEVERITY_LEVELS.MEDIUM,
    validate: (val) => {
      if (!val) {
        return { status: 'missing', evidence: 'Header not observed in response' };
      }
      const upper = val.toUpperCase().trim();
      if (!['DENY', 'SAMEORIGIN'].some(v => upper.startsWith(v))) {
        return {
          status: 'warning',
          evidence: `Value '${val}' is non-standard. 'DENY' or 'SAMEORIGIN' recommended.`
        };
      }
      return { status: 'present', evidence: `Configured with value '${val}'` };
    }
  },
  {
    id: 'header-referrer-policy',
    headerName: 'referrer-policy',
    displayName: 'Referrer-Policy',
    severity: SEVERITY_LEVELS.LOW,
    validate: (val) => {
      if (!val) {
        return { status: 'missing', evidence: 'Header not observed in response' };
      }
      return { status: 'present', evidence: `Configured with value '${val}'` };
    }
  },
  {
    id: 'header-permissions-policy',
    headerName: 'permissions-policy',
    displayName: 'Permissions-Policy',
    severity: SEVERITY_LEVELS.LOW,
    validate: (val) => {
      if (!val) {
        return { status: 'missing', evidence: 'Header not observed in response' };
      }
      return { status: 'present', evidence: `Configured: ${val.substring(0, 150)}${val.length > 150 ? '...' : ''}` };
    }
  }
];

/**
 * Scans HTTP response headers and returns normalized findings.
 *
 * @param {Object} headers - Response headers dictionary (lowercase keys)
 * @param {boolean} [isHttps=true] - Whether target URL is HTTPS
 * @returns {Array<Object>} List of standardized findings
 */
function scanHeaders(headers = {}, isHttps = true) {
  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }

  const findings = [];

  for (const check of REQUIRED_HEADERS) {
    const rawVal = normalizedHeaders[check.headerName];
    const evaluation = check.validate(rawVal, isHttps);

    if (!evaluation) continue;

    if (evaluation.status === 'missing' || evaluation.status === 'warning') {
      findings.push(
        normalizeFinding({
          id: check.id,
          category: FINDING_CATEGORIES.SECURITY_HEADER,
          name: check.displayName,
          status: evaluation.status,
          severity: check.severity,
          evidence: evaluation.evidence
        })
      );
    }
  }

  return findings;
}

module.exports = {
  scanHeaders,
  REQUIRED_HEADERS
};
