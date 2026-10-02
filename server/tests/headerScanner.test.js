/**
 * Security Headers Scanner Tests
 * Covers:
 *  - Scenario 7: Security-header detection (when headers are present)
 *  - Scenario 8: Missing security-header detection (when headers are absent)
 */

const assert = require('assert');
const { scanHeaders } = require('../src/scanners/headerScanner');

async function testHeaderScanner() {
  console.log('--- Running Header Scanner Tests ---');

  // Test 1: All Security Headers Missing
  const emptyHeaders = {};
  const missingFindings = scanHeaders(emptyHeaders, true);

  const missingIds = missingFindings.map(f => f.id);
  assert(missingIds.includes('header-csp'), 'Should report missing Content-Security-Policy');
  assert(missingIds.includes('header-hsts'), 'Should report missing Strict-Transport-Security on HTTPS');
  assert(missingIds.includes('header-x-content-type-options'), 'Should report missing X-Content-Type-Options');
  assert(missingIds.includes('header-x-frame-options'), 'Should report missing X-Frame-Options');
  assert(missingIds.includes('header-referrer-policy'), 'Should report missing Referrer-Policy');
  assert(missingIds.includes('header-permissions-policy'), 'Should report missing Permissions-Policy');

  // Check deterministic severity rules
  const cspFinding = missingFindings.find(f => f.id === 'header-csp');
  assert.strictEqual(cspFinding.severity, 'high');
  assert.strictEqual(cspFinding.status, 'missing');

  const hstsFinding = missingFindings.find(f => f.id === 'header-hsts');
  assert.strictEqual(hstsFinding.severity, 'medium');

  console.log('  [PASS] 8. Missing security-header detection and deterministic severity verified');

  // Test 2: All Required Headers Present and Secure
  const secureHeaders = {
    'content-security-policy': "default-src 'self'",
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=(), camera=()'
  };

  const secureFindings = scanHeaders(secureHeaders, true);
  assert.strictEqual(secureFindings.length, 0, 'No warning/missing findings should be reported for properly configured headers');
  console.log('  [PASS] 7. Security-header detection for configured policies verified');

  // Test 3: Insecure/Non-standard header values
  const weakHeaders = {
    'content-security-policy': "default-src 'self'",
    'strict-transport-security': 'max-age=31536000',
    'x-content-type-options': 'sniff-allowed', // invalid
    'x-frame-options': 'ALLOWALL', // invalid
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=*'
  };
  const weakFindings = scanHeaders(weakHeaders, true);
  const weakIds = weakFindings.map(f => f.id);
  assert(weakIds.includes('header-x-content-type-options'), 'Should flag non-nosniff X-Content-Type-Options');
  assert(weakIds.includes('header-x-frame-options'), 'Should flag non-standard X-Frame-Options');
  console.log('  [PASS] Non-standard header values flagged with appropriate status');

  return true;
}

if (require.main === module) {
  testHeaderScanner()
    .then(() => console.log('All Header Scanner tests passed!'))
    .catch(err => {
      console.error('Header Scanner test failed:', err);
      process.exit(1);
    });
}

module.exports = { testHeaderScanner };
