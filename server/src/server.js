/**
 * Server Bootstrap
 * Loads environment variables, configures port, and initializes HTTP listener.
 */

require('dotenv').config();
const app = require('./app');
const { logger } = require('./logging/logger');

const PORT = parseInt(process.env.PORT, 10) || 5000;

const server = app.listen(PORT, () => {
  logger.info('server_started', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    service: 'PatchLens Security Scanner Backend'
  });
});

// Graceful Shutdown
function handleShutdown(signal) {
  logger.info('shutdown_signal_received', { signal });
  server.close(() => {
    logger.info('server_closed');
    process.exit(0);
  });

  // Force exit if close takes too long
  setTimeout(() => {
    logger.error('force_shutdown_timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

module.exports = server;
