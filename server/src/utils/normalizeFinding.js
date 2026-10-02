/**
 * Deterministic Finding Normalization and Severity Matrix
 */

const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

const FINDING_CATEGORIES = {
  SECURITY_HEADER: 'security_header',
  TLS_CONFIG: 'tls_configuration',
  TECHNOLOGY: 'technology_fingerprint',
  VULNERABILITY: 'vulnerability_advisory',
  NETWORK: 'network_policy'
};

const DEFAULT_SEVERITY_RULES = {
  // Security Header Findings
  'header-csp': SEVERITY_LEVELS.HIGH,
  'header-hsts': SEVERITY_LEVELS.MEDIUM,
  'header-x-content-type-options': SEVERITY_LEVELS.MEDIUM,
  'header-x-frame-options': SEVERITY_LEVELS.MEDIUM,
  'header-referrer-policy': SEVERITY_LEVELS.LOW,
  'header-permissions-policy': SEVERITY_LEVELS.LOW,

  // TLS Findings
  'tls-invalid-cert': SEVERITY_LEVELS.HIGH,
  'tls-expired-cert': SEVERITY_LEVELS.CRITICAL,
  'tls-weak-protocol': SEVERITY_LEVELS.HIGH,
  'tls-unsupported': SEVERITY_LEVELS.MEDIUM,
  'tls-expiring-soon': SEVERITY_LEVELS.LOW,

  // Default fallback
  'default': SEVERITY_LEVELS.LOW
};

/**
 * Normalizes a finding into the agreed standard contract.
 *
 * @param {Object} params
 * @param {string} params.id - Unique deterministic ID (e.g. 'header-csp')
 * @param {string} params.category - Category (e.g. 'security_header', 'tls_configuration')
 * @param {string} params.name - Human-readable name
 * @param {string} params.status - 'missing' | 'present' | 'warning' | 'insecure' | 'valid' | 'vulnerable'
 * @param {string} [params.severity] - 'critical' | 'high' | 'medium' | 'low' | 'info'
 * @param {string} params.evidence - Detailed observation / evidence string
 * @param {Object} [params.details] - Optional extra metadata
 * @returns {Object} Standardized finding object matching API response contract
 */
function normalizeFinding({ id, category, name, status, severity, evidence, details }) {
  const resolvedSeverity = severity || DEFAULT_SEVERITY_RULES[id] || DEFAULT_SEVERITY_RULES.default;

  const finding = {
    id: id || `finding_${Math.random().toString(36).substring(2, 9)}`,
    category: category || FINDING_CATEGORIES.SECURITY_HEADER,
    name: name || 'Security Assessment Finding',
    status: status || 'info',
    severity: resolvedSeverity,
    evidence: evidence || 'No additional evidence recorded.'
  };

  if (details && Object.keys(details).length > 0) {
    finding.details = details;
  }

  return finding;
}

module.exports = {
  SEVERITY_LEVELS,
  FINDING_CATEGORIES,
  DEFAULT_SEVERITY_RULES,
  normalizeFinding
};
