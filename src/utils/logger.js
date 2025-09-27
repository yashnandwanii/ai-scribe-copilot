const winston = require('winston');
const path = require('path');

// Avoid any filesystem writes/creates during module import so serverless
// environments (Vercel, Lambda) won't fail with ENOENT or EACCES.
// File logging is only enabled explicitly via LOCAL_LOGS=1 in non-serverless
// local development.
const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.FUNCTIONS_WORKER_RUNTIME);
const enableFileLogs = process.env.LOCAL_LOGS === '1' && !isServerless && process.env.NODE_ENV !== 'production';
const logsDir = path.join(__dirname, '../../logs');

// Define a compact JSON-friendly format for structured logging
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Always include a Console transport
const transports = [
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  })
];

// Only attempt to add file transports when explicitly enabled (local dev).
// Do NOT create directories here; if the directory doesn't exist, skip file
// transports silently to avoid mkdir errors in restricted filesystems.
if (enableFileLogs) {
  try {
    const fs = require('fs');
    if (fs.existsSync(logsDir)) {
      transports.push(
        new winston.transports.File({ filename: path.join(logsDir, 'error.log'), level: 'error', maxsize: 5 * 1024 * 1024, maxFiles: 5 }),
        new winston.transports.File({ filename: path.join(logsDir, 'combined.log'), maxsize: 5 * 1024 * 1024, maxFiles: 5 }),
        new winston.transports.File({ filename: path.join(logsDir, 'app.log'), level: 'warn', maxsize: 5 * 1024 * 1024, maxFiles: 3 })
      );
    }
  } catch (e) {
    // Swallow any filesystem related errors and continue with Console-only logging
  }
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'medication-app-backend' },
  transports
});

// Keep exception/rejection handlers simple and console-based to avoid filesystem
// interactions in serverless environments.
logger.exceptions.handle(new winston.transports.Console());
logger.rejections.handle(new winston.transports.Console());

// Add a development-only pretty console output when not in production
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple(),
      winston.format.printf(({ timestamp, level, message, ...meta }) => {
        const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
        return `${timestamp} ${level}: ${message} ${metaStr}`;
      })
    )
  }));
}

// Morgan stream compatibility
logger.stream = {
  write: (msg) => {
    logger.info(msg.trim());
  }
};

// Lightweight structured helpers
logger.logRequest = (req, res, responseTime) => {
  logger.info('HTTP Request', {
    method: req.method,
    url: req.url,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get && req.get('User-Agent'),
    ip: req.ip,
    userId: req.user && req.user.id
  });
};

logger.logError = (error, req = null) => {
  const payload = {
    message: error && error.message,
    name: error && error.name,
    stack: error && error.stack
  };
  if (req) {
    payload.request = {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userId: req.user && req.user.id
    };
  }
  logger.error('Application Error', payload);
};

logger.logSecurity = (event, details = {}, req = null) => {
  const payload = { event, details, timestamp: new Date().toISOString() };
  if (req) payload.request = { ip: req.ip, userAgent: req.get && req.get('User-Agent') };
  logger.warn('Security Event', payload);
};

logger.logPerformance = (operation, duration, metadata = {}) => {
  logger.info('Performance Metric', { operation, duration: `${duration}ms`, ...metadata });
};

logger.logDatabase = (operation, collection, duration, error = null) => {
  const dbLog = { operation, collection, duration: `${duration}ms` };
  if (error) logger.error('Database Error', { ...dbLog, error: error.message });
  else logger.info('Database Operation', dbLog);
};

logger.logAuth = (event, userId, details = {}) => {
  logger.info('Authentication Event', { event, userId, timestamp: new Date().toISOString(), ...details });
};

module.exports = logger;