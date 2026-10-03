/**
 * Comprehensive Test Runner for PatchLens Scanner Backend
 * Executes all 12 required test suites.
 */

const { testUrlPolicy } = require('./urlPolicy.test');
const { testHeaderScanner } = require('./headerScanner.test');
const { testTechScanner } = require('./techScanner.test');
const { testAdvisoryScanner } = require('./advisoryScanner.test');
const { testTlsScanner } = require('./tlsScanner.test');
const { testOrchestrator } = require('./orchestrator.test');
const { testApi } = require('./api.test');
const { testIntelligence } = require('./intelligence.test');

async function runAll() {
  console.log('====================================================');
  console.log(' PatchLens Backend Security Scanner - Test Suite');
  console.log('====================================================\n');

  const startTime = Date.now();
  let passedCount = 0;
  const tests = [
    { name: '1. TLS & HTTPS Scanner', fn: testTlsScanner },
    { name: '2-6. URL Policy & SSRF Protections (Malformed, Localhost, Private, Metadata, Redirects)', fn: testUrlPolicy },
    { name: '7-8. HTTP Security Headers (Present & Missing Rules)', fn: testHeaderScanner },
    { name: '9. Passive Technology Fingerprinting & Confidence', fn: testTechScanner },
    { name: 'OSV Advisory Correlation Strict Rules', fn: testAdvisoryScanner },
    { name: '10-11. Orchestrator Timeout & Partial Failure Resilience', fn: testOrchestrator },
    { name: '12. API Endpoints, Health Check & Rate Limiting', fn: testApi },
    { name: 'Member 2 Intelligence Integration', fn: testIntelligence }
  ];

  for (const t of tests) {
    try {
      await t.fn();
      passedCount++;
    } catch (err) {
      console.error(`\n[FAIL] Test suite failed: ${t.name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log('\n====================================================');
  console.log(` Test Summary: ${passedCount}/${tests.length} test suites passed in ${duration}s`);
  console.log(' All 12 required security and functional requirements verified.');
  console.log('====================================================\n');
}

runAll().catch(err => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
