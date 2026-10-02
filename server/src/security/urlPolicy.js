/**
 * URL Policy and SSRF Protection Module
 * Validates URLs and prevents requests to private, loopback, link-local,
 * cloud metadata, or reserved networks.
 */

const dns = require('dns').promises;
const net = require('net');

// Known cloud metadata hostnames
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'instance-data',
  'instance-data.ec2.internal'
]);

/**
 * Checks whether an IPv4 address belongs to a private, loopback, or reserved range.
 */
function isBlockedIPv4(ip) {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed IPv4
  }

  const [b0, b1, b2, b3] = parts;

  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return true;

  // 127.0.0.0/8 (Loopback)
  if (b0 === 127) return true;

  // 10.0.0.0/8 (Private-Use)
  if (b0 === 10) return true;

  // 100.64.0.0/10 (Carrier-grade NAT / Shared Address Space)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

  // 169.254.0.0/16 (Link-Local & Cloud Metadata e.g. 169.254.169.254)
  if (b0 === 169 && b1 === 254) return true;

  // 172.16.0.0/12 (Private-Use)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (b0 === 192 && b1 === 0 && b2 === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1)
  if (b0 === 192 && b1 === 0 && b2 === 2) return true;

  // 192.168.0.0/16 (Private-Use)
  if (b0 === 192 && b1 === 168) return true;

  // 198.18.0.0/15 (Network Interconnect Benchmarking)
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (b0 === 198 && b1 === 51 && b2 === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (b0 === 203 && b1 === 0 && b2 === 113) return true;

  // 224.0.0.0/4 (Multicast)
  if (b0 >= 224 && b0 <= 239) return true;

  // 240.0.0.0/4 (Reserved / Future Use) & 255.255.255.255 (Broadcast)
  if (b0 >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address belongs to a private, loopback, link-local,
 * or reserved range.
 */
function isBlockedIPv6(ip) {
  const normalized = ip.toLowerCase();

  // :: (Unspecified) and ::1 (Loopback)
  if (normalized === '::' || normalized === '::1' || normalized === '0:0:0:0:0:0:0:1' || normalized === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:') || normalized.startsWith('0:0:0:0:0:ffff:')) {
    const v4Part = normalized.replace(/^.*:ffff:/, '');
    if (net.isIPv4(v4Part)) {
      return isBlockedIPv4(v4Part);
    }
    return true;
  }

  // Unique Local Address (fc00::/7 - fc00:: and fd00::)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true;
  }

  // Link-Local Unicast (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) {
    return true;
  }

  return false;
}

/**
 * Checks if an IP is blocked (either v4 or v6).
 */
function isBlockedIP(ip) {
  const ipType = net.isIP(ip);
  if (ipType === 4) {
    return isBlockedIPv4(ip);
  } else if (ipType === 6) {
    return isBlockedIPv6(ip);
  }
  return true; // Not a valid IP
}

/**
 * Validates a target URL against SSRF rules and resolves DNS to ensure
 * the destination does not point to internal/private infrastructure.
 *
 * @param {string} targetUrl - URL string to validate
 * @returns {Promise<{isValid: boolean, reason?: string, parsedUrl?: URL, resolvedIps?: string[]}>}
 */
async function validateTargetUrl(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return { isValid: false, reason: 'Target URL must be a non-empty string' };
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    return { isValid: false, reason: 'Malformed URL: Unable to parse' };
  }

  // Enforce http/https protocols only
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { isValid: false, reason: `Unsupported protocol: ${parsed.protocol}. Only http: and https: are permitted.` };
  }

  // Reject embedded credentials
  if (parsed.username || parsed.password) {
    return { isValid: false, reason: 'URLs with embedded credentials are not permitted' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Check against static blocked hostnames
  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    return { isValid: false, reason: `Access to host '${hostname}' is prohibited (SSRF protection)` };
  }

  // If hostname is directly an IP address
  if (net.isIP(hostname)) {
    if (isBlockedIP(hostname)) {
      return { isValid: false, reason: `Access to IP '${hostname}' is prohibited (Private/Reserved IP)` };
    }
    return {
      isValid: true,
      parsedUrl: parsed,
      resolvedIps: [hostname]
    };
  }

  // Resolve hostname via DNS
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      return { isValid: false, reason: `Could not resolve hostname: ${hostname}` };
    }

    const resolvedIps = addresses.map(a => a.address);

    // Validate every resolved IP
    for (const addr of addresses) {
      if (isBlockedIP(addr.address)) {
        return {
          isValid: false,
          reason: `Hostname ${hostname} resolved to prohibited IP ${addr.address} (SSRF protection)`
        };
      }
    }

    return {
      isValid: true,
      parsedUrl: parsed,
      resolvedIps
    };
  } catch (dnsErr) {
    return { isValid: false, reason: `DNS resolution failed for host '${hostname}': ${dnsErr.message}` };
  }
}

module.exports = {
  validateTargetUrl,
  isBlockedIP,
  isBlockedIPv4,
  isBlockedIPv6
};
