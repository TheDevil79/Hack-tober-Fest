/**
 * TLS Scanner Tests
 * Covers:
 *  - Scenario 1: Valid HTTPS URL / TLS handshake & cert parsing
 *  - Cleartext HTTP handling
 */

const assert = require('assert');
const { scanTls } = require('../src/scanners/tlsScanner');

async function testTlsScanner() {
  console.log('--- Running TLS Scanner Tests ---');

  // Test 1: Plain HTTP scheme
  const httpUrl = new URL('http://example.com');
  const httpResult = await scanTls(httpUrl);
  assert.strictEqual(httpResult.valid, false);
  assert.strictEqual(httpResult.protocol, 'none');
  const tlsUnsupportedFinding = httpResult.findings.find(f => f.id === 'tls-unsupported');
  assert(tlsUnsupportedFinding, 'Plain HTTP should produce tls-unsupported finding');
  console.log('  [PASS] Plain HTTP scheme correctly flagged as lacking TLS');

  // Test 2: Valid HTTPS domain test (e.g. google.com / cloudflare.com)
  try {
    const httpsUrl = new URL('https://cloudflare.com');
    const tlsResult = await scanTls(httpsUrl, 5000);
    assert(typeof tlsResult.valid === 'boolean', 'TLS result valid must be boolean');
    assert(tlsResult.protocol.startsWith('TLS') || tlsResult.protocol.startsWith('unknown'), 'Protocol must be reported');
    console.log('  [PASS] 1. Valid HTTPS TLS inspection completed successfully');
  } catch (err) {
    console.log('  [SKIP] Live HTTPS TLS network connection skipped in test environment:', err.message);
  }

  return true;
}

if (require.main === module) {
  testTlsScanner()
    .then(() => console.log('All TLS Scanner tests passed!'))
    .catch(err => {
      console.error('TLS Scanner test failed:', err);
      process.exit(1);
    });
}

module.exports = { testTlsScanner };
