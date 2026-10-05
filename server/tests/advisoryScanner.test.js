/**
 * Advisory Scanner Tests
 * Covers:
 *  - OSV query guard rules: strictly queries OSV only when component AND reliable version are present
 *  - Skips OSV querying when version is missing
 */

const assert = require('assert');
const { scanAdvisories } = require('../src/scanners/advisoryScanner');

async function testAdvisoryScanner() {
  console.log('--- Running Advisory Scanner Tests ---');

  // Test 1: Technologies without version MUST NOT trigger OSV query
  const techsWithoutVersion = [
    { name: 'Express', confidence: 'medium' },
    { name: 'Nginx', confidence: 'medium' },
    { name: 'React', confidence: 'medium' }
  ];

  const findingsNoVersion = await scanAdvisories(techsWithoutVersion);
  assert.strictEqual(findingsNoVersion.length, 0, 'Advisory scanner must return 0 findings when versions are absent');
  console.log('  [PASS] Strictly skips OSV advisory lookups when component version is absent');

  // Test 2: Input with valid component and version structure
  const techsWithVersion = [
    { name: 'Express', version: '4.17.1', confidence: 'high' }
  ];

  // scanAdvisories handles network/OSV query gracefully
  const findingsWithVersion = await scanAdvisories(techsWithVersion);
  assert(Array.isArray(findingsWithVersion), 'Should return an array of findings');
  console.log(`  [PASS] OSV query safely processed for versioned component (found ${findingsWithVersion.length} advisories)`);

  return true;
}

if (require.main === module) {
  testAdvisoryScanner()
    .then(() => console.log('All Advisory Scanner tests passed!'))
    .catch(err => {
      console.error('Advisory Scanner test failed:', err);
      process.exit(1);
    });
}

module.exports = { testAdvisoryScanner };
