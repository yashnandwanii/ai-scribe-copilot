const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');

/**
 * Global Error Handler Middleware
 * Handles all errors thrown in the application
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error details
  logger.logError(err, req);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Invalid resource ID format';
    return ResponseUtils.error(res, message, 400);
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `Duplicate value for ${field}. This ${field} already exists.`;
    return ResponseUtils.error(res, message, 409);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(error => ({
      field: error.path,
      message: error.message,
      value: error.value,
    }));
    return ResponseUtils.validationError(res, errors);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return ResponseUtils.unauthorized(res, 'Invalid authentication token');
  }

  if (err.name === 'TokenExpiredError') {
    return ResponseUtils.unauthorized(res, 'Authentication token has expired');
  }

  // Multer errors (file upload)
  if (err.code === 'LIMIT_FILE_SIZE') {
    return ResponseUtils.error(res, 'File size too large', 413);
  }

  if (err.code === 'LIMIT_FILE_COUNT') {
    return ResponseUtils.error(res, 'Too many files uploaded', 413);
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return ResponseUtils.error(res, 'Unexpected file field', 400);
  }

  // AWS S3 errors
  if (err.code === 'NoSuchBucket') {
    logger.error('AWS S3 Bucket not found:', err);
    return ResponseUtils.error(res, 'File storage service unavailable');
  }

  if (err.code === 'AccessDenied') {
    logger.error('AWS S3 Access denied:', err);
    return ResponseUtils.error(res, 'File storage access denied');
  }

  // Rate limiting errors
  if (err.type === 'entity.too.large') {
    return ResponseUtils.error(res, 'Request entity too large', 413);
  }

  // MongoDB connection errors
  if (err.name === 'MongoError' || err.name === 'MongooseError') {
    logger.error('Database error:', err);
    return ResponseUtils.error(res, 'Database service unavailable');
  }

  // Redis connection errors
  if (err.name === 'ReplyError' || err.code === 'ECONNREFUSED') {
    logger.error('Redis error:', err);
    // Don't expose Redis errors to client, continue without caching
    return ResponseUtils.error(res, 'Service temporarily unavailable');
  }

  // Custom application errors
  if (err.isOperational) {
    return ResponseUtils.error(res, err.message, err.statusCode || 500);
  }

  // Syntax errors in production
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return ResponseUtils.error(res, 'Invalid JSON format', 400);
  }

  // Default to 500 server error
  const message = process.env.NODE_ENV === 'production' 
    ? 'Something went wrong' 
    : error.message;

  return ResponseUtils.error(res, message, 500, {
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
};

/**
 * Async Error Handler Wrapper
 * Wraps async route handlers to catch errors
 */
const asyncErrorHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Custom Application Error Class
 */
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = isOperational;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Unhandled Route Error Handler
 * Handles requests to non-existent routes
 */
const notFound = (req, res, next) => {
  const message = `Route ${req.originalUrl} not found`;
  logger.logSecurity('route_not_found', { 
    url: req.originalUrl, 
    method: req.method 
  }, req);
  
  const error = new AppError(message, 404);
  next(error);
};

/**
 * Validation Error Formatter
 * Formats validation errors from different sources
 */
const formatValidationError = (errors) => {
  if (Array.isArray(errors)) {
    return errors.map(error => ({
      field: error.param || error.path || error.field,
      message: error.msg || error.message,
      value: error.value,
    }));
  }

  if (errors.details) {
    // Joi validation errors
    return errors.details.map(error => ({
      field: error.path.join('.'),
      message: error.message,
      value: error.context?.value,
    }));
  }

  return errors;
};

/**
 * Database Connection Error Handler
 */
const handleDatabaseError = (error) => {
  logger.error('Database connection error:', error);
  
  // Attempt to reconnect
  setTimeout(() => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      logger.info('Attempting to reconnect to database...');
      require('../config/database')();
    }
  }, 5000);
};

/**
 * Graceful Shutdown Handler
 */
const gracefulShutdown = (server) => {
  return (signal) => {
    logger.info(`Received ${signal}. Graceful shutdown initiated.`);
    
    server.close(() => {
      logger.info('HTTP server closed.');
      
      // Close database connections
      const mongoose = require('mongoose');
      mongoose.connection.close(() => {
        logger.info('Database connection closed.');
        
        // Close Redis connection
        const redisClient = require('../config/redis');
        redisClient.quit(() => {
          logger.info('Redis connection closed.');
          process.exit(0);
        });
      });
    });

    // Force close after 30 seconds
    setTimeout(() => {
      logger.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 30000);
  };
};

/**
 * Security Error Handler
 * Handles security-related errors and logs them
 */
const handleSecurityError = (error, req) => {
  const securityEvents = {
    'invalid_signature': 'Invalid request signature detected',
    'tampered_request': 'Request tampering detected',
    'suspicious_activity': 'Suspicious activity detected',
    'rate_limit_exceeded': 'Rate limit exceeded',
    'brute_force_attempt': 'Brute force attempt detected',
  };

  if (securityEvents[error.type]) {
    logger.logSecurity(error.type, {
      message: error.message,
      details: error.details,
    }, req);
  }
};

/**
 * Performance Monitoring Error Handler
 */
const handlePerformanceError = (error, operation, startTime) => {
  const duration = Date.now() - startTime;
  
  logger.logPerformance(operation, duration, {
    error: error.message,
    success: false,
  });
};

module.exports = {
  errorHandler,
  asyncErrorHandler,
  AppError,
  notFound,
  formatValidationError,
  handleDatabaseError,
  gracefulShutdown,
  handleSecurityError,
  handlePerformanceError,
};