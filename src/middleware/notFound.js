const ResponseUtils = require('../utils/response');

/**
 * 404 Not Found Middleware
 * Handles requests to non-existent routes
 */
const notFound = (req, res, next) => {
  return ResponseUtils.notFound(res, `Route ${req.originalUrl} not found`);
};

module.exports = { notFound };