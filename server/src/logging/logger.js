/**
 * Structured logger with sensitive-data redaction.
 */

const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  'secret',
  'token',
  'jwt',
  'api_key',
  'apikey',
  'llm_api_key',
  'mongodb_uri',
  'key'
]);

function redactSensitiveData(obj, depth = 0) {
  if (depth > 5 || obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => redactSensitiveData(item, depth + 1));
  }

  const redacted = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_KEYS.has(lowerKey) || lowerKey.includes('secret') || lowerKey.includes('password') || lowerKey.includes('token') || lowerKey.includes('key')) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactSensitiveData(value, depth + 1);
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}

const logger = {
  info: (event, data = {}) => {
    const entry = {
      timestamp: new Date().toISOString(),
      level: 'INFO',
      event,
      ...redactSensitiveData(data)
    };
    console.log(JSON.stringify(entry));
  },
  warn: (event, data = {}) => {
    const entry = {
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event,
      ...redactSensitiveData(data)
    };
    console.warn(JSON.stringify(entry));
  },
  error: (event, data = {}) => {
    const entry = {
      timestamp: new Date().toISOString(),
      level: 'ERROR',
      event,
      ...redactSensitiveData(data)
    };
    console.error(JSON.stringify(entry));
  },
  debug: (event, data = {}) => {
    if (process.env.DEBUG === 'true' || process.env.NODE_ENV === 'development') {
      const entry = {
        timestamp: new Date().toISOString(),
        level: 'DEBUG',
        event,
        ...redactSensitiveData(data)
      };
      console.log(JSON.stringify(entry));
    }
  }
};

module.exports = {
  logger,
  redactSensitiveData
};
