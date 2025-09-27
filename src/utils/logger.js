const winston = require('winston');
const path = require('path');

// Initialize logger without file system operations for serverless compatibility
let logsDir;
let canWriteFiles = false;

try {
  const fs = require('fs');
  logsDir = path.join(__dirname, '../../logs');
  
  // Only attempt file operations in non-serverless environments
  if (!process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_NAME && process.env.NODE_ENV !== 'production') {
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
    canWriteFiles = true;
  }
} catch (error) {
  // Completely silent failure - serverless environments should use console only
  canWriteFiles = false;
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Create transports array (conditional file logging)
const transports = [];

// Always add console transport
transports.push(new winston.transports.Console({
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.simple()
  )
}));

// Add file transports only if we can write files
if (canWriteFiles) {
  transports.push(
    // Write all logs with importance level of 'error' or less to 'error.log'
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    
    // Write all logs with importance level of 'info' or less to 'combined.log'
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    
    // Write all logs with importance level of 'warn' or less to 'app.log'
    new winston.transports.File({
      filename: path.join(logsDir, 'app.log'),
      level: 'warn',
      maxsize: 5242880, // 5MB
      maxFiles: 3,
    })
  );
}

// Create logger with dynamic transports
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'medication-app-backend' },
  transports: transports,
  
  // Handle exceptions and rejections (conditional)
  exceptionHandlers: canWriteFiles ? [
    new winston.transports.File({
      filename: path.join(logsDir, 'exceptions.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 3,
    })
  ] : [new winston.transports.Console()],
  
  rejectionHandlers: canWriteFiles ? [
    new winston.transports.File({
      filename: path.join(logsDir, 'rejections.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 3,
    })
  ] : [new winston.transports.Console()]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple(),
      winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
        return `${timestamp} [${service}] ${level}: ${message} ${
          Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
        }`;
      })
    )
  }));
}

// Create a stream object for Morgan HTTP logging
logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

// Helper methods for structured logging
logger.logRequest = (req, res, responseTime) => {
  logger.info('HTTP Request', {
    method: req.method,
    url: req.url,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    userId: req.user?.id,
  });
};

logger.logError = (error, req = null) => {
  const errorInfo = {
    message: error.message,
    stack: error.stack,
    name: error.name,
  };

  if (req) {
    errorInfo.request = {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body,
      params: req.params,
      query: req.query,
      ip: req.ip,
      userId: req.user?.id,
    };
  }

  logger.error('Application Error', errorInfo);
};

logger.logSecurity = (event, details, req = null) => {
  const securityLog = {
    event,
    details,
    timestamp: new Date().toISOString(),
  };

  if (req) {
    securityLog.request = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url,
      method: req.method,
      userId: req.user?.id,
    };
  }

  logger.warn('Security Event', securityLog);
};

logger.logPerformance = (operation, duration, metadata = {}) => {
  logger.info('Performance Metric', {
    operation,
    duration: `${duration}ms`,
    ...metadata,
  });
};

logger.logDatabase = (operation, collection, duration, error = null) => {
  const dbLog = {
    operation,
    collection,
    duration: `${duration}ms`,
  };

  if (error) {
    dbLog.error = error.message;
    logger.error('Database Error', dbLog);
  } else {
    logger.info('Database Operation', dbLog);
  }
};

logger.logAuth = (event, userId, details = {}) => {
  logger.info('Authentication Event', {
    event,
    userId,
    timestamp: new Date().toISOString(),
    ...details,
  });
};

module.exports = logger;