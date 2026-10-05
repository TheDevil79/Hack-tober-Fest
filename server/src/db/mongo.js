const { MongoClient } = require('mongodb');
const dns = require('dns');
const { logger } = require('../logging/logger');

let client;
let database;
let connectionPromise;
let lastFailure;
let lastFailureAt = 0;
let lastWarningAt = 0;

function unavailable(message, cause) {
  const error = new Error(message);
  error.code = 'MONGODB_UNAVAILABLE';
  error.cause = cause;
  return error;
}

function configureDns() {
  const servers = (process.env.DNS_SERVERS || '')
    .split(',')
    .map(server => server.trim())
    .filter(Boolean);

  if (servers.length > 0) dns.setServers(servers);
}

async function connect() {
  if (!process.env.MONGODB_URI) {
    throw unavailable('MongoDB is not configured');
  }

  configureDns();
  const timeoutMs = parseInt(process.env.MONGODB_TIMEOUT_MS, 10) || 3000;
  client = new MongoClient(process.env.MONGODB_URI, {
    connectTimeoutMS: timeoutMs,
    serverSelectionTimeoutMS: timeoutMs
  });

  try {
    await client.connect();
    database = client.db(process.env.MONGODB_DB || 'patchlens');
    await Promise.all([
      database.collection('scans').createIndex({ scanId: 1 }, { unique: true }),
      database.collection('scans').createIndex({ target: 1, createdAt: -1 }),
      database.collection('remediationCache').createIndex({ cacheKey: 1 }, { unique: true }),
      database.collection('users').createIndex({ usernameKey: 1 }, { unique: true }),
      database.collection('users').createIndex({ emailKey: 1 }, { unique: true })
    ]);
    lastFailure = undefined;
    lastFailureAt = 0;
    logger.info('mongodb_connected', { database: process.env.MONGODB_DB || 'patchlens' });
    return database;
  } catch (error) {
    if (client) await client.close().catch(() => {});
    client = undefined;
    database = undefined;
    throw unavailable('MongoDB is temporarily unavailable', error);
  }
}

async function getDb() {
  if (database) return database;

  const retryDelayMs = parseInt(process.env.MONGODB_RETRY_DELAY_MS, 10) || 10000;
  if (lastFailure && Date.now() - lastFailureAt < retryDelayMs) throw lastFailure;

  if (!connectionPromise) {
    connectionPromise = connect()
      .catch(error => {
        lastFailure = error;
        lastFailureAt = Date.now();
        throw error;
      })
      .finally(() => {
        connectionPromise = undefined;
      });
  }
  return connectionPromise;
}

async function tryGetDb() {
  try {
    return await getDb();
  } catch (error) {
    const warningIntervalMs = parseInt(process.env.MONGODB_WARNING_INTERVAL_MS, 10) || 10000;
    if (Date.now() - lastWarningAt >= warningIntervalMs) {
      logger.warn('mongodb_unavailable', { message: error.message });
      lastWarningAt = Date.now();
    }
    return null;
  }
}

async function closeDb() {
  if (client) await client.close();
  client = undefined;
  database = undefined;
  connectionPromise = undefined;
  lastFailure = undefined;
  lastFailureAt = 0;
  lastWarningAt = 0;
}

module.exports = { getDb, tryGetDb, closeDb };
