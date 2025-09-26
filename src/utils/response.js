const logger = require('./logger');

class ResponseUtils {
  /**
   * Send success response
   * @param {object} res - Express response object
   * @param {any} data - Response data
   * @param {string} message - Success message
   * @param {number} statusCode - HTTP status code
   */
  static success(res, data = null, message = 'Success', statusCode = 200) {
    const response = {
      success: true,
      message,
      data,
      timestamp: new Date().toISOString(),
    };

    // Add pagination info if data has pagination
    if (data && typeof data === 'object' && data.pagination) {
      response.pagination = data.pagination;
      response.data = data.results || data.data;
    }

    return res.status(statusCode).json(response);
  }

  /**
   * Send error response
   * @param {object} res - Express response object
   * @param {string} message - Error message
   * @param {number} statusCode - HTTP status code
   * @param {any} errors - Detailed errors
   */
  static error(res, message = 'Internal Server Error', statusCode = 500, errors = null) {
    const response = {
      success: false,
      message,
      timestamp: new Date().toISOString(),
    };

    // Only include error details in development
    if (process.env.NODE_ENV === 'development' && errors) {
      response.errors = errors;
    }

    // Log error for monitoring
    logger.error('API Error Response', {
      message,
      statusCode,
      errors,
    });

    return res.status(statusCode).json(response);
  }

  /**
   * Send validation error response
   * @param {object} res - Express response object
   * @param {array} validationErrors - Array of validation errors
   */
  static validationError(res, validationErrors) {
    const formattedErrors = validationErrors.map(error => ({
      field: error.path || error.param,
      message: error.message || error.msg,
      value: error.value,
    }));

    return this.error(res, 'Validation failed', 400, formattedErrors);
  }

  /**
   * Send unauthorized response
   * @param {object} res - Express response object
   * @param {string} message - Error message
   */
  static unauthorized(res, message = 'Unauthorized access') {
    return this.error(res, message, 401);
  }

  /**
   * Send forbidden response
   * @param {object} res - Express response object
   * @param {string} message - Error message
   */
  static forbidden(res, message = 'Forbidden access') {
    return this.error(res, message, 403);
  }

  /**
   * Send not found response
   * @param {object} res - Express response object
   * @param {string} message - Error message
   */
  static notFound(res, message = 'Resource not found') {
    return this.error(res, message, 404);
  }

  /**
   * Send too many requests response
   * @param {object} res - Express response object
   * @param {string} message - Error message
   */
  static tooManyRequests(res, message = 'Too many requests') {
    return this.error(res, message, 429);
  }

  /**
   * Send paginated response
   * @param {object} res - Express response object
   * @param {array} data - Array of data
   * @param {number} page - Current page
   * @param {number} limit - Items per page
   * @param {number} total - Total items
   * @param {string} message - Success message
   */
  static paginated(res, data, page, limit, total, message = 'Success') {
    const totalPages = Math.ceil(total / limit);
    const hasNext = page < totalPages;
    const hasPrev = page > 1;

    const response = {
      success: true,
      message,
      data,
      pagination: {
        current_page: page,
        per_page: limit,
        total_items: total,
        total_pages: totalPages,
        has_next: hasNext,
        has_prev: hasPrev,
        next_page: hasNext ? page + 1 : null,
        prev_page: hasPrev ? page - 1 : null,
      },
      timestamp: new Date().toISOString(),
    };

    return res.status(200).json(response);
  }

  /**
   * Send created response
   * @param {object} res - Express response object
   * @param {any} data - Created resource data
   * @param {string} message - Success message
   */
  static created(res, data, message = 'Resource created successfully') {
    return this.success(res, data, message, 201);
  }

  /**
   * Send updated response
   * @param {object} res - Express response object
   * @param {any} data - Updated resource data
   * @param {string} message - Success message
   */
  static updated(res, data, message = 'Resource updated successfully') {
    return this.success(res, data, message, 200);
  }

  /**
   * Send deleted response
   * @param {object} res - Express response object
   * @param {string} message - Success message
   */
  static deleted(res, message = 'Resource deleted successfully') {
    return this.success(res, null, message, 200);
  }

  /**
   * Send no content response
   * @param {object} res - Express response object
   */
  static noContent(res) {
    return res.status(204).send();
  }

  /**
   * Sanitize data for response (remove sensitive fields)
   * @param {object} data - Data to sanitize
   * @param {array} fieldsToRemove - Fields to remove
   * @returns {object} Sanitized data
   */
  static sanitizeResponse(data, fieldsToRemove = ['password', 'salt', '__v']) {
    if (!data || typeof data !== 'object') return data;

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeResponse(item, fieldsToRemove));
    }

    // Handle Mongoose documents
    const sanitizedData = data.toObject ? data.toObject() : { ...data };

    fieldsToRemove.forEach(field => {
      delete sanitizedData[field];
    });

    return sanitizedData;
  }

  /**
   * Format validation errors from express-validator
   * @param {array} errors - Express-validator errors
   * @returns {array} Formatted errors
   */
  static formatValidationErrors(errors) {
    return errors.array().map(error => ({
      field: error.path,
      message: error.msg,
      value: error.value,
      location: error.location,
    }));
  }

  /**
   * Create API response wrapper for async handlers
   * @param {function} handler - Async route handler
   * @returns {function} Wrapped handler
   */
  static asyncHandler(handler) {
    return (req, res, next) => {
      Promise.resolve(handler(req, res, next)).catch(next);
    };
  }

  /**
   * Standardize error response format
   * @param {Error} error - Error object
   * @param {object} req - Express request object
   * @returns {object} Standardized error
   */
  static standardizeError(error, req = null) {
    let statusCode = 500;
    let message = 'Internal Server Error';

    // Handle different error types
    if (error.name === 'ValidationError') {
      statusCode = 400;
      message = 'Validation Error';
    } else if (error.name === 'CastError') {
      statusCode = 400;
      message = 'Invalid ID format';
    } else if (error.code === 11000) {
      statusCode = 409;
      message = 'Duplicate entry';
    } else if (error.name === 'JsonWebTokenError') {
      statusCode = 401;
      message = 'Invalid token';
    } else if (error.name === 'TokenExpiredError') {
      statusCode = 401;
      message = 'Token expired';
    } else if (error.message) {
      message = error.message;
    }

    // Log error with request context
    if (req) {
      logger.logError(error, req);
    }

    return {
      statusCode,
      message,
      originalError: process.env.NODE_ENV === 'development' ? error : undefined,
    };
  }
}

module.exports = ResponseUtils;