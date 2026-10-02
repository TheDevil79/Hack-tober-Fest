/**
 * Technology Scanner Tests
 * Covers:
 *  - Scenario 9: Passive technology detection with confidence scoring
 *  - Reliable vs absent version extraction
 */

const assert = require('assert');
const { scanTechnologies } = require('../src/scanners/techScanner');

async function testTechScanner() {
  console.log('--- Running Technology Scanner Tests ---');

  // Test 1: Header-based detection (Server + X-Powered-By)
  const headers = {
    'server': 'Apache/2.4.51 (Unix) OpenSSL/1.1.1',
    'x-powered-by': 'Express'
  };
  const body = '';

  const detected = scanTechnologies(headers, body);

  const apache = detected.find(t => t.name.toLowerCase() === 'apache');
  assert(apache, 'Apache should be detected');
  assert.strictEqual(apache.confidence, 'high');
  assert.strictEqual(apache.version, '2.4.51', 'Reliable version should be extracted');

  const express = detected.find(t => t.name.toLowerCase() === 'express');
  assert(express, 'Express should be detected');
  assert.strictEqual(express.confidence, 'medium');
  assert.strictEqual(express.version, undefined, 'No version should be inferred when not provided');

  // Test 2: HTML-based detection (Meta generator, framework markers)
  const htmlHeaders = {};
  const htmlBody = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="generator" content="WordPress 6.2.1" />
        <link rel="stylesheet" href="/assets/bootstrap-5.3.0.min.css" />
      </head>
      <body>
        <div id="root">
          <div data-reactroot="">Hello React</div>
        </div>
        <script src="/js/jquery-3.6.0.min.js"></script>
        <script src="/_next/static/chunks/main.js"></script>
      </body>
    </html>
  `;

  const htmlDetected = scanTechnologies(htmlHeaders, htmlBody);

  const wp = htmlDetected.find(t => t.name.toLowerCase() === 'wordpress');
  assert(wp, 'WordPress should be detected from meta generator');
  assert.strictEqual(wp.confidence, 'high');
  assert.strictEqual(wp.version, '6.2.1');

  const react = htmlDetected.find(t => t.name.toLowerCase() === 'react');
  assert(react, 'React should be detected from DOM markers');

  const next = htmlDetected.find(t => t.name.toLowerCase() === 'next.js');
  assert(next, 'Next.js should be detected from _next asset path');

  const jquery = htmlDetected.find(t => t.name.toLowerCase() === 'jquery');
  assert(jquery, 'jQuery should be detected');
  assert.strictEqual(jquery.version, '3.6.0');

  console.log('  [PASS] 9. Passive technology fingerprinting & strict confidence scoring verified');
  return true;
}

if (require.main === module) {
  testTechScanner()
    .then(() => console.log('All Tech Scanner tests passed!'))
    .catch(err => {
      console.error('Tech Scanner test failed:', err);
      process.exit(1);
    });
}

module.exports = { testTechScanner };
