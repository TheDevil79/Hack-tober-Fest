/**
 * Controlled HTTP Client with SSRF-safe redirect resolution,
 * timeout controls, and response body size bounding.
 */

const http = require('http');
const https = require('https');
const { validateTargetUrl } = require('../security/urlPolicy');
const { logger } = require('../logging/logger');

const MAX_BODY_BYTES = 512 * 1024; // 512 KB
const MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS, 10) || 10000;

/**
 * Performs a single HTTP/HTTPS request with safety guards.
 */
function fetchSingle(targetUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const transport = parsed.protocol === 'https:' ? https : http;

    const reqOptions = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'PatchLens-Security-Scanner/1.0 (+https://patchlens.security)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close'
      },
      timeout: timeoutMs,
      // For defensive testing, we don't reject unauthorized TLS at the HTTP transport level
      // so we can inspect headers even if the cert is self-signed (tlsScanner handles cert audit)
      rejectUnauthorized: false
    };

    const req = transport.request(reqOptions, (res) => {
      let body = '';
      let bodyLength = 0;
      let truncated = false;

      res.setEncoding('utf8');

      res.on('data', (chunk) => {
        if (bodyLength + chunk.length <= MAX_BODY_BYTES) {
          body += chunk;
          bodyLength += chunk.length;
        } else if (!truncated) {
          const remaining = MAX_BODY_BYTES - bodyLength;
          if (remaining > 0) {
            body += chunk.slice(0, remaining);
            bodyLength += remaining;
          }
          truncated = true;
          // Stop receiving more data to save memory
          req.destroy();
        }
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers: res.headers,
          body,
          truncated
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`HTTP request timed out after ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      // If we destroyed it due to truncation, treat as success with truncated body
      if (req.destroyed && err.message.includes('socket hang up')) {
        resolve({
          statusCode: 200,
          headers: {},
          body: '',
          truncated: true
        });
      } else {
        reject(err);
      }
    });

    req.end();
  });
}

/**
 * Safely fetches a URL following redirects with SSRF validation on every hop.
 *
 * @param {string} initialUrl
 * @param {Object} [options]
 * @param {number} [options.timeoutMs]
 * @param {number} [options.maxRedirects]
 * @returns {Promise<{statusCode: number, headers: Object, body: string, finalUrl: string, redirectChain: string[]}>}
 */
async function safeFetch(initialUrl, options = {}) {
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects !== undefined ? options.maxRedirects : MAX_REDIRECTS;

  let currentUrl = initialUrl;
  let redirectCount = 0;
  const redirectChain = [initialUrl];

  while (redirectCount <= maxRedirects) {
    // 1. SSRF check before every request hop
    const policyResult = await validateTargetUrl(currentUrl);
    if (!policyResult.isValid) {
      logger.warn('ssrf_blocked_redirect', {
        target: initialUrl,
        hop: currentUrl,
        reason: policyResult.reason
      });
      throw new Error(`SSRF Protection: Redirect destination rejected - ${policyResult.reason}`);
    }

    // 2. Fetch target
    const result = await fetchSingle(currentUrl, timeoutMs);

    // 3. Handle redirects (301, 302, 303, 307, 308)
    const isRedirect = [301, 302, 303, 307, 308].includes(result.statusCode);
    const location = result.headers.location;

    if (isRedirect && location) {
      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new Error(`Exceeded maximum redirect limit of ${maxRedirects}`);
      }

      // Resolve relative redirect location against current URL
      const nextUrl = new URL(location, currentUrl).toString();
      redirectChain.push(nextUrl);
      currentUrl = nextUrl;
      continue;
    }

    return {
      statusCode: result.statusCode,
      headers: result.headers,
      body: result.body,
      finalUrl: currentUrl,
      redirectChain
    };
  }

  throw new Error(`Exceeded maximum redirect limit of ${maxRedirects}`);
}

module.exports = {
  safeFetch,
  MAX_BODY_BYTES,
  DEFAULT_TIMEOUT_MS
};
