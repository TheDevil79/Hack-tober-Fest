const assert = require('assert');
const http = require('http');
const app = require('../src/app');
const { saveAndEnrichScan } = require('../src/services/scans');

function makeRequest(server, { method, path, body }) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const request = http.request({
      hostname: '127.0.0.1',
      port: server.address().port,
      path,
      method,
      headers: postData ? {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      } : {}
    }, response => {
      let data = '';
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        body: JSON.parse(data)
      }));
    });
    request.on('error', reject);
    if (postData) request.write(postData);
    request.end();
  });
}

async function testIntelligence() {
  console.log('--- Running Intelligence Integration Tests ---');
  const originalMongoUri = process.env.MONGODB_URI;
  const originalGeminiKey = process.env.GEMINI_API_KEY;
  delete process.env.MONGODB_URI;
  delete process.env.GEMINI_API_KEY;

  const target = `https://authorized-test.invalid/${Date.now()}`;
  const previousId = `scan_previous_${Date.now()}`;
  const currentId = `scan_current_${Date.now()}`;

  try {
    const previous = await saveAndEnrichScan({
      scanId: previousId,
      target,
      technologies: [],
      findings: [
        { id: 'header-csp', name: 'Content-Security-Policy', status: 'missing' },
        { id: 'header-x-frame-options', name: 'X-Frame-Options', status: 'present' }
      ]
    });
    const current = await saveAndEnrichScan({
      scanId: currentId,
      target,
      technologies: [],
      findings: [
        { id: 'header-csp', name: 'Content-Security-Policy', status: 'present' },
        { id: 'header-x-frame-options', name: 'X-Frame-Options', status: 'present' },
        { id: 'header-hsts', name: 'Strict-Transport-Security', status: 'missing' }
      ]
    });

    assert.strictEqual(previous.persistence.storage, 'memory');
    assert.strictEqual(current.persistence.available, false);
    assert(current.findings.every(finding => finding.remediationUnavailable));
    console.log('  [PASS] Scan enrichment degrades safely without MongoDB or Gemini');

    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const stored = await makeRequest(server, {
        method: 'GET',
        path: `/api/intelligence/scans/${currentId}`
      });
      assert.strictEqual(stored.statusCode, 200);
      assert.strictEqual(stored.body.scanId, currentId);

      const history = await makeRequest(server, {
        method: 'GET',
        path: `/api/intelligence/history?target=${encodeURIComponent(target)}`
      });
      assert.strictEqual(history.statusCode, 200);
      assert.strictEqual(history.body.length, 2);

      const comparison = await makeRequest(server, {
        method: 'POST',
        path: '/api/intelligence/compare',
        body: { currentId, previousId }
      });
      assert.strictEqual(comparison.statusCode, 200);
      assert.deepStrictEqual(comparison.body.fixed, ['Content-Security-Policy']);
      assert(comparison.body.unchanged.includes('X-Frame-Options'));
      assert.deepStrictEqual(comparison.body.newIssues, ['Strict-Transport-Security']);
      console.log('  [PASS] Stored scan, history, and before/after comparison endpoints work');
    } finally {
      server.close();
    }
  } finally {
    if (originalMongoUri === undefined) delete process.env.MONGODB_URI;
    else process.env.MONGODB_URI = originalMongoUri;
    if (originalGeminiKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalGeminiKey;
  }

  return true;
}

if (require.main === module) {
  testIntelligence().catch(error => {
    console.error('Intelligence integration test failed:', error);
    process.exit(1);
  });
}

module.exports = { testIntelligence };
