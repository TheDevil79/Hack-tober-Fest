/**
 * Demo Target Scan Workflow
 * Tests POST /api/scan against an authorized public demonstration target (https://example.com)
 */

const { executeScan } = require('../src/scanners/scanOrchestrator');

async function runDemo() {
  const target = process.argv[2] || 'https://example.com';
  console.log(`\nInitiating PatchLens defensive scan on authorized target: ${target}\n`);

  try {
    const result = await executeScan(target);
    console.log('--- Scan Response Result ---');
    console.log(JSON.stringify(result, null, 2));
    console.log('----------------------------\n');
  } catch (err) {
    console.error('Demo scan failed:', err.message);
  }
}

if (require.main === module) {
  runDemo();
}

module.exports = { runDemo };
