/**
 * URL Policy & SSRF Protection Tests
 * Covers:
 *  - Scenario 2: Malformed URLs
 *  - Scenario 3: Localhost rejection
 *  - Scenario 4: Private IP rejection (10.x, 192.168.x, 172.16.x)
 *  - Scenario 5: Metadata IP rejection (169.254.169.254, metadata.google.internal)
 *  - Scenario 6: Redirect to private destination
 */

const assert = require('assert');
const { validateTargetUrl, isBlockedIP } = require('../src/security/urlPolicy');
const { safeFetch } = require('../src/utils/httpClient');
const http = require('http');

async function testUrlPolicy() {
  console.log('--- Running URL Policy & SSRF Protection Tests ---');

  // Test 1: Malformed URLs
  const malformedResults = [
    await validateTargetUrl(''),
    await validateTargetUrl('not-a-valid-url'),
    await validateTargetUrl('ftp://example.com'),
    await validateTargetUrl('javascript:alert(1)'),
    await validateTargetUrl('http://user:pass@example.com')
  ];
  for (const res of malformedResults) {
    assert.strictEqual(res.isValid, false, 'Malformed URL should be rejected');
  }
  console.log('  [PASS] 2. Malformed URLs rejected correctly');

  // Test 2: Localhost Rejection
  const localhostResults = [
    await validateTargetUrl('http://localhost'),
    await validateTargetUrl('http://localhost:8080'),
    await validateTargetUrl('http://127.0.0.1'),
    await validateTargetUrl('http://127.0.0.2:3000'),
    await validateTargetUrl('http://[::1]')
  ];
  for (const res of localhostResults) {
    assert.strictEqual(res.isValid, false, 'Localhost URL should be rejected');
  }
  console.log('  [PASS] 3. Localhost & loopback URLs rejected correctly');

  // Test 3: Private IP Rejection
  const privateIps = [
    '10.0.0.1',
    '10.254.0.1',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.1.1',
    '192.168.0.254',
    '100.64.0.1', // Carrier grade NAT
    'fc00::1',    // IPv6 Unique Local
    'fd12:3456::1'
  ];
  for (const ip of privateIps) {
    assert.strictEqual(isBlockedIP(ip), true, `Private IP ${ip} must be blocked`);
    const res = await validateTargetUrl(`http://${ip.includes(':') ? `[${ip}]` : ip}`);
    assert.strictEqual(res.isValid, false, `URL with private IP ${ip} must be rejected`);
  }
  console.log('  [PASS] 4. Private IPv4/IPv6 ranges rejected correctly');

  // Test 4: Cloud Metadata IP Rejection
  const metadataHosts = [
    'http://169.254.169.254',
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal',
    'http://instance-data'
  ];
  for (const metaUrl of metadataHosts) {
    const res = await validateTargetUrl(metaUrl);
    assert.strictEqual(res.isValid, false, `Metadata URL ${metaUrl} must be rejected`);
  }
  console.log('  [PASS] 5. Cloud metadata destinations rejected correctly');

  // Test 5: Redirect to Private Destination Rejection
  // Spin up temporary redirecting server
  const redirectServer = http.createServer((req, res) => {
    if (req.url === '/redirect-to-private') {
      res.writeHead(302, { 'Location': 'http://169.254.169.254/secret' });
      res.end();
    } else if (req.url === '/redirect-to-loopback') {
      res.writeHead(302, { 'Location': 'http://127.0.0.1:8080/admin' });
      res.end();
    }
  });

  await new Promise((resolve) => redirectServer.listen(0, '127.0.0.1', resolve));
  const port = redirectServer.address().port;

  try {
    // Attempting to fetch a redirect that targets metadata or loopback
    // Note: safeFetch validates intermediate hop with validateTargetUrl
    let threw = false;
    try {
      await safeFetch(`http://127.0.0.1:${port}/redirect-to-private`, { timeoutMs: 2000 });
    } catch (err) {
      threw = true;
      assert(err.message.includes('SSRF Protection') || err.message.includes('rejected'), 'Should mention SSRF or rejection');
    }
    assert.strictEqual(threw, true, 'Redirect to private destination should be blocked');
    console.log('  [PASS] 6. Redirect into blocked destination prevented correctly');
  } finally {
    redirectServer.close();
  }

  return true;
}

if (require.main === module) {
  testUrlPolicy()
    .then(() => console.log('All URL Policy tests passed!'))
    .catch(err => {
      console.error('URL Policy test failed:', err);
      process.exit(1);
    });
}

module.exports = { testUrlPolicy };
