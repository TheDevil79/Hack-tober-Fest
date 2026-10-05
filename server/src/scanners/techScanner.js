/**
 * Passive Technology Fingerprinting Scanner
 * Evaluates passive, non-invasive indicators (Server, X-Powered-By, HTML/script markers)
 * Assigns confidence scores and extracts version ONLY when evidence is strictly explicit.
 */

/**
 * Validates if a string is a reliable semantic / numerical version.
 */
function isReliableVersion(str) {
  if (!str || typeof str !== 'string') return false;
  const cleaned = str.replace(/^[vV]/, '').replace(/[(),;]/g, '').trim();
  // Strictly requires digits with dots (e.g. 6.2.1, 2.4.51, 18.0)
  return /^[0-9]+(\.[0-9]+)+([-_a-zA-Z0-9]+)?$/.test(cleaned) || /^[0-9]+\.[0-9]+$/.test(cleaned);
}

/**
 * Parses header and meta strings for software names and reliable versions.
 * Supports slash-separated (Apache/2.4.51) and space-separated (WordPress 6.2.1) formats.
 */
function parseHeaderToken(headerVal) {
  if (!headerVal || typeof headerVal !== 'string') return [];
  const results = [];

  const tokens = headerVal.split(/\s+/).map(t => t.replace(/[(),;]/g, '').trim()).filter(Boolean);

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const slashIdx = token.indexOf('/');

    if (slashIdx > 0) {
      const name = token.substring(0, slashIdx).trim();
      const rawVer = token.substring(slashIdx + 1).trim();
      if (name && name.length < 30) {
        const hasValidVer = isReliableVersion(rawVer);
        results.push({
          name,
          version: hasValidVer ? rawVer.replace(/^[vV]/, '') : undefined,
          confidence: 'high'
        });
      }
    } else if (token.length > 1 && token.length < 30) {
      // Check if the next token is a reliable version (e.g. "WordPress" followed by "6.2.1")
      const nextToken = tokens[i + 1];
      if (nextToken && isReliableVersion(nextToken)) {
        results.push({
          name: token,
          version: nextToken.replace(/^[vV]/, ''),
          confidence: 'high'
        });
        i++; // Consume the version token
      } else if (!isReliableVersion(token)) {
        // Just a software name without version
        results.push({
          name: token,
          confidence: 'medium'
        });
      }
    }
  }

  return results;
}

/**
 * Passively identifies technologies and returns list with confidence and optional version.
 *
 * @param {Object} headers - Response headers
 * @param {string} body - Response HTML body
 * @returns {Array<{name: string, confidence: 'high'|'medium'|'low', version?: string, evidence?: string}>}
 */
function scanTechnologies(headers = {}, body = '') {
  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }

  const detectedMap = new Map();

  function addDetection(name, confidence, version = undefined, evidence = undefined) {
    const key = name.toLowerCase();
    const existing = detectedMap.get(key);

    if (!existing) {
      detectedMap.set(key, { name, confidence, version, evidence });
    } else {
      // Elevate confidence if stronger evidence found
      const rank = { high: 3, medium: 2, low: 1 };
      if (rank[confidence] > rank[existing.confidence]) {
        existing.confidence = confidence;
      }
      if (version && !existing.version) {
        existing.version = version;
      }
      if (evidence && !existing.evidence) {
        existing.evidence = evidence;
      }
    }
  }

  // 1. Analyze Server header
  if (normalizedHeaders['server']) {
    const serverTokens = parseHeaderToken(normalizedHeaders['server']);
    for (const token of serverTokens) {
      addDetection(token.name, token.confidence, token.version, `Server header: ${normalizedHeaders['server']}`);
    }
  }

  // 2. Analyze X-Powered-By header
  if (normalizedHeaders['x-powered-by']) {
    const poweredTokens = parseHeaderToken(normalizedHeaders['x-powered-by']);
    for (const token of poweredTokens) {
      addDetection(token.name, token.confidence, token.version, `X-Powered-By header: ${normalizedHeaders['x-powered-by']}`);
    }
  }

  // 3. Analyze specific known framework headers
  if (normalizedHeaders['x-aspnet-version'] || normalizedHeaders['x-aspnetmvc-version']) {
    const v = normalizedHeaders['x-aspnet-version'] || normalizedHeaders['x-aspnetmvc-version'];
    const validVer = /^[0-9]+(\.[0-9]+)*$/.test(v) ? v : undefined;
    addDetection('ASP.NET', 'high', validVer, `X-AspNet-Version header: ${v}`);
  }

  if (normalizedHeaders['x-drupal-cache']) {
    addDetection('Drupal', 'high', undefined, 'X-Drupal-Cache header present');
  }

  if (normalizedHeaders['x-varnish']) {
    addDetection('Varnish', 'high', undefined, 'X-Varnish cache header present');
  }

  if (normalizedHeaders['via'] && normalizedHeaders['via'].toLowerCase().includes('vegur')) {
    addDetection('Heroku', 'medium', undefined, 'Via header marker (Vegur)');
  }

  if (normalizedHeaders['cf-ray'] || normalizedHeaders['server']?.toLowerCase().includes('cloudflare')) {
    addDetection('Cloudflare', 'high', undefined, 'Cloudflare network headers present');
  }

  // 4. Analyze HTML Body markers
  if (body && typeof body === 'string') {
    const lowerBody = body.toLowerCase();

    // Meta generator tag (e.g. <meta name="generator" content="WordPress 6.2" />)
    const metaGeneratorMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) ||
                               body.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
    if (metaGeneratorMatch && metaGeneratorMatch[1]) {
      const content = metaGeneratorMatch[1].trim();
      const tokens = parseHeaderToken(content);
      if (tokens.length > 0) {
        for (const t of tokens) {
          addDetection(t.name, 'high', t.version, `Meta generator tag: ${content}`);
        }
      } else {
        addDetection(content, 'high', undefined, `Meta generator tag: ${content}`);
      }
    }

    // WordPress path markers
    if (lowerBody.includes('/wp-content/') || lowerBody.includes('/wp-includes/')) {
      addDetection('WordPress', 'medium', undefined, 'WordPress path markers in HTML (/wp-content/)');
    }

    // Next.js markers
    if (lowerBody.includes('/_next/') || lowerBody.includes('__next_data__')) {
      addDetection('Next.js', 'high', undefined, 'Next.js asset paths & data attributes');
    }

    // Nuxt.js markers
    if (lowerBody.includes('/_nuxt/') || lowerBody.includes('__nuxt')) {
      addDetection('Nuxt.js', 'high', undefined, 'Nuxt.js asset paths & client marker');
    }

    // React markers
    if (lowerBody.includes('data-reactroot') || lowerBody.includes('react-dom') || lowerBody.includes('id="root"')) {
      addDetection('React', 'medium', undefined, 'React DOM markers');
    }

    // Vue.js markers
    if (lowerBody.includes('data-v-') || lowerBody.includes('vue.js') || lowerBody.includes('vue.min.js')) {
      addDetection('Vue.js', 'medium', undefined, 'Vue scoped styles / script markers');
    }

    // Bootstrap markers
    const bootstrapMatch = body.match(/bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)(\.min)?\.css/i);
    if (bootstrapMatch && bootstrapMatch[1]) {
      addDetection('Bootstrap', 'high', bootstrapMatch[1], `Bootstrap CSS link (v${bootstrapMatch[1]})`);
    } else if (lowerBody.includes('bootstrap.min.css') || lowerBody.includes('bootstrap.css')) {
      addDetection('Bootstrap', 'medium', undefined, 'Bootstrap CSS stylesheet reference');
    }

    // jQuery markers
    const jqueryMatch = body.match(/jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(\.min)?\.js/i);
    if (jqueryMatch && jqueryMatch[1]) {
      addDetection('jQuery', 'high', jqueryMatch[1], `jQuery script reference (v${jqueryMatch[1]})`);
    } else if (lowerBody.includes('jquery.min.js') || lowerBody.includes('jquery.js')) {
      addDetection('jQuery', 'medium', undefined, 'jQuery script reference');
    }
  }

  // Return clean list of objects matching contract
  return Array.from(detectedMap.values()).map(tech => {
    const item = {
      name: tech.name,
      confidence: tech.confidence
    };
    if (tech.version) {
      item.version = tech.version;
    }
    if (tech.evidence) {
      item.evidence = tech.evidence;
    }
    return item;
  });
}

module.exports = {
  scanTechnologies,
  parseHeaderToken
};
