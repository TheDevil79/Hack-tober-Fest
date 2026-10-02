/**
 * Defensive TLS & HTTPS Configuration Scanner
 * Inspects certificate validity, expiration, protocol version, and HTTPS availability.
 */

const tls = require('tls');
const net = require('net');
const { normalizeFinding, FINDING_CATEGORIES, SEVERITY_LEVELS } = require('../utils/normalizeFinding');

/**
 * Performs a TLS connection to inspect the certificate and handshake attributes.
 *
 * @param {string} hostname
 * @param {number} [port=443]
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<Object>}
 */
function inspectTlsCertificate(hostname, port = 443, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let resolved = false;

    const socket = tls.connect({
      host: hostname,
      port: port,
      servername: net.isIP(hostname) ? undefined : hostname,
      rejectUnauthorized: false, // defensive inspection: capture cert details even if untrusted
      timeout: timeoutMs
    }, () => {
      if (resolved) return;
      resolved = true;

      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;

      socket.destroy();

      if (!cert || Object.keys(cert).length === 0) {
        resolve({
          valid: false,
          available: false,
          protocol: protocol || 'unknown',
          error: 'No peer certificate presented'
        });
        return;
      }

      const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null;
      const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
      const now = new Date();
      const expirationDate = cert.valid_to ? new Date(cert.valid_to) : null;
      const daysRemaining = expirationDate ? Math.round((expirationDate - now) / (1000 * 60 * 60 * 24)) : null;
      const isExpired = daysRemaining !== null && daysRemaining < 0;

      resolve({
        available: true,
        valid: authorized && !isExpired,
        protocol: protocol || 'unknown',
        issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Unknown') : 'Unknown',
        subject: cert.subject ? (cert.subject.CN || cert.subject.O || 'Unknown') : 'Unknown',
        validFrom,
        validTo,
        daysRemaining,
        isExpired,
        authorized,
        authorizationError: authError ? String(authError) : null,
        cipherName: cipher ? cipher.name : null
      });
    });

    socket.on('timeout', () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        reject(new Error(`TLS connection timed out after ${timeoutMs}ms`));
      }
    });

    socket.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        reject(err);
      }
    });
  });
}

/**
 * Executes the TLS scan for a given URL and returns standardized findings.
 *
 * @param {URL} targetUrl - Parsed target URL
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<{tlsResult: Object, findings: Array}>}
 */
async function scanTls(targetUrl, timeoutMs = 5000) {
  const findings = [];
  const isHttps = targetUrl.protocol === 'https:';
  const port = parseInt(targetUrl.port, 10) || (isHttps ? 443 : 80);
  const hostname = targetUrl.hostname;

  if (!isHttps && port !== 443) {
    // Target was requested via plain HTTP
    findings.push(
      normalizeFinding({
        id: 'tls-unsupported',
        category: FINDING_CATEGORIES.TLS_CONFIG,
        name: 'HTTPS Transport Not Used',
        status: 'insecure',
        severity: SEVERITY_LEVELS.MEDIUM,
        evidence: `Target URL scheme is '${targetUrl.protocol}'. Cleartext HTTP does not provide encryption or integrity protection.`
      })
    );

    return {
      valid: false,
      protocol: 'none',
      available: false,
      findings
    };
  }

  try {
    const certInfo = await inspectTlsCertificate(hostname, port, timeoutMs);

    if (!certInfo.available) {
      findings.push(
        normalizeFinding({
          id: 'tls-unsupported',
          category: FINDING_CATEGORIES.TLS_CONFIG,
          name: 'TLS Certificate Missing',
          status: 'insecure',
          severity: SEVERITY_LEVELS.HIGH,
          evidence: certInfo.error || 'Server did not present a valid TLS certificate during handshake.'
        })
      );
    } else {
      // Check certificate expiration
      if (certInfo.isExpired) {
        findings.push(
          normalizeFinding({
            id: 'tls-expired-cert',
            category: FINDING_CATEGORIES.TLS_CONFIG,
            name: 'Expired TLS Certificate',
            status: 'insecure',
            severity: SEVERITY_LEVELS.CRITICAL,
            evidence: `Certificate expired on ${certInfo.validTo} (${Math.abs(certInfo.daysRemaining)} days ago).`
          })
        );
      } else if (certInfo.daysRemaining !== null && certInfo.daysRemaining < 14) {
        findings.push(
          normalizeFinding({
            id: 'tls-expiring-soon',
            category: FINDING_CATEGORIES.TLS_CONFIG,
            name: 'TLS Certificate Expiring Soon',
            status: 'warning',
            severity: SEVERITY_LEVELS.LOW,
            evidence: `Certificate will expire in ${certInfo.daysRemaining} days (on ${certInfo.validTo}).`
          })
        );
      }

      // Check certificate authorization / trust chain
      if (!certInfo.authorized) {
        findings.push(
          normalizeFinding({
            id: 'tls-invalid-cert',
            category: FINDING_CATEGORIES.TLS_CONFIG,
            name: 'Untrusted or Self-Signed TLS Certificate',
            status: 'insecure',
            severity: SEVERITY_LEVELS.HIGH,
            evidence: `Certificate validation failed: ${certInfo.authorizationError || 'Self-signed or untrusted authority'}.`
          })
        );
      }

      // Check protocol version (TLSv1.0 or TLSv1.1 are considered deprecated)
      if (['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(certInfo.protocol)) {
        findings.push(
          normalizeFinding({
            id: 'tls-weak-protocol',
            category: FINDING_CATEGORIES.TLS_CONFIG,
            name: 'Deprecated TLS Protocol Version',
            status: 'insecure',
            severity: SEVERITY_LEVELS.HIGH,
            evidence: `Server negotiated deprecated protocol ${certInfo.protocol}. TLS 1.2 or TLS 1.3 is recommended.`
          })
        );
      }
    }

    return {
      valid: certInfo.valid,
      protocol: certInfo.protocol,
      issuer: certInfo.issuer,
      subject: certInfo.subject,
      validFrom: certInfo.validFrom,
      validTo: certInfo.validTo,
      daysRemaining: certInfo.daysRemaining,
      findings
    };
  } catch (err) {
    findings.push(
      normalizeFinding({
        id: 'tls-unsupported',
        category: FINDING_CATEGORIES.TLS_CONFIG,
        name: 'TLS Handshake Failed',
        status: 'error',
        severity: SEVERITY_LEVELS.HIGH,
        evidence: `Unable to establish TLS connection: ${err.message}`
      })
    );

    return {
      valid: false,
      protocol: 'unknown',
      error: err.message,
      findings
    };
  }
}

module.exports = {
  scanTls,
  inspectTlsCertificate
};
