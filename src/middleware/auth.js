const jwt = require('jsonwebtoken');
const User = require('../models/User');
const SecurityUtils = require('../utils/security');
const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');
const redisClient = require('../config/redis');

/**
 * JWT Authentication Middleware
 * Verifies JWT token and attaches user to request
 */
const authenticate = async (req, res, next) => {
  try {
    let token;

    // Check for token in Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Check for token in cookies
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      logger.logSecurity('authentication_failed', { reason: 'no_token' }, req);
      return ResponseUtils.unauthorized(res, 'Access token required');
    }

    try {
      // Verify token
      const decoded = SecurityUtils.verifyToken(token);
      
      // Check if token is blacklisted
      const isBlacklisted = await redisClient.get(`blacklist:${token}`);
      if (isBlacklisted) {
        logger.logSecurity('authentication_failed', { reason: 'blacklisted_token' }, req);
        return ResponseUtils.unauthorized(res, 'Token has been revoked');
      }

      // Check if user still exists
      const user = await User.findById(decoded.userId).select('-password');
      if (!user) {
        logger.logSecurity('authentication_failed', { reason: 'user_not_found', userId: decoded.userId }, req);
        return ResponseUtils.unauthorized(res, 'User no longer exists');
      }

      // Check if user is active
      if (!user.isActive) {
        logger.logSecurity('authentication_failed', { reason: 'user_inactive', userId: user._id }, req);
        return ResponseUtils.unauthorized(res, 'Account has been deactivated');
      }

      // Check if password was changed after token was issued
      if (user.passwordChangedAt && decoded.iat < Math.floor(user.passwordChangedAt.getTime() / 1000)) {
        logger.logSecurity('authentication_failed', { reason: 'password_changed', userId: user._id }, req);
        return ResponseUtils.unauthorized(res, 'Password has been changed. Please log in again');
      }

      // Attach user to request
      req.user = user;
      req.token = token;

      // Update last activity
      user.lastActivity = new Date();
      await user.save();

      // Log successful authentication
      logger.logAuth('token_verified', user._id, { ip: req.ip });

      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        logger.logSecurity('authentication_failed', { reason: 'token_expired' }, req);
        return ResponseUtils.unauthorized(res, 'Token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        logger.logSecurity('authentication_failed', { reason: 'invalid_token' }, req);
        return ResponseUtils.unauthorized(res, 'Invalid token');
      } else {
        logger.logError(error, req);
        return ResponseUtils.error(res, 'Authentication failed');
      }
    }
  } catch (error) {
    logger.logError(error, req);
    return ResponseUtils.error(res, 'Authentication failed');
  }
};

/**
 * Optional Authentication Middleware
 * Attaches user to request if token is provided, but doesn't require it
 */
const optionalAuth = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (token) {
    try {
      const decoded = SecurityUtils.verifyToken(token);
      const user = await User.findById(decoded.userId).select('-password');
      
      if (user && user.isActive) {
        req.user = user;
        req.token = token;
      }
    } catch (error) {
      // Silently ignore token errors for optional auth
      logger.info('Optional auth token invalid:', error.message);
    }
  }

  next();
};

/**
 * Authorization Middleware Factory
 * Checks if user has required roles/permissions
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return ResponseUtils.unauthorized(res, 'Authentication required');
    }

    const userRole = req.user.role;
    
    if (!roles.includes(userRole)) {
      logger.logSecurity('authorization_failed', {
        userId: req.user._id,
        userRole,
        requiredRoles: roles,
      }, req);
      return ResponseUtils.forbidden(res, 'Insufficient permissions');
    }

    logger.logAuth('authorization_success', req.user._id, {
      userRole,
      requiredRoles: roles,
    });

    next();
  };
};

/**
 * Resource Ownership Middleware
 * Checks if user owns the requested resource
 */
const checkOwnership = (Model, resourceIdParam = 'id', userField = 'doctorId') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return ResponseUtils.unauthorized(res, 'Authentication required');
      }

      const resourceId = req.params[resourceIdParam];
      if (!resourceId) {
        return ResponseUtils.error(res, 'Resource ID required', 400);
      }

      const resource = await Model.findById(resourceId);
      if (!resource) {
        return ResponseUtils.notFound(res, 'Resource not found');
      }

      // Check if user owns the resource or is admin
      const userId = req.user._id.toString();
      const resourceUserId = resource[userField] ? resource[userField].toString() : null;

      if (req.user.role !== 'admin' && userId !== resourceUserId) {
        logger.logSecurity('ownership_violation', {
          userId,
          resourceId,
          resourceType: Model.modelName,
        }, req);
        return ResponseUtils.forbidden(res, 'Access denied to this resource');
      }

      // Attach resource to request for use in route handler
      req.resource = resource;
      next();
    } catch (error) {
      logger.logError(error, req);
      return ResponseUtils.error(res, 'Authorization failed');
    }
  };
};

/**
 * Session Ownership Middleware
 * Checks if user owns the session through patient ownership
 */
const checkSessionOwnership = async (req, res, next) => {
  try {
    const Session = require('../models/Session');
    const Patient = require('../models/Patient');

    if (!req.user) {
      return ResponseUtils.unauthorized(res, 'Authentication required');
    }

    const sessionId = req.params.sessionId || req.params.id;
    if (!sessionId) {
      return ResponseUtils.error(res, 'Session ID required', 400);
    }

    const session = await Session.findById(sessionId).populate('patientId');
    if (!session) {
      return ResponseUtils.notFound(res, 'Session not found');
    }

    // Check if user owns the patient associated with this session
    const userId = req.user._id.toString();
    const patientDoctorId = session.patientId.doctorId.toString();

    if (req.user.role !== 'admin' && userId !== patientDoctorId) {
      logger.logSecurity('session_ownership_violation', {
        userId,
        sessionId,
        patientId: session.patientId._id,
      }, req);
      return ResponseUtils.forbidden(res, 'Access denied to this session');
    }

    req.session = session;
    next();
  } catch (error) {
    logger.logError(error, req);
    return ResponseUtils.error(res, 'Authorization failed');
  }
};

/**
 * API Key Authentication Middleware
 * For server-to-server communication
 */
const authenticateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return ResponseUtils.unauthorized(res, 'API key required');
    }

    // Check if API key exists and is valid
    const hashedKey = SecurityUtils.hashData(apiKey);
    const keyData = await redisClient.get(`api_key:${hashedKey}`);
    
    if (!keyData) {
      logger.logSecurity('api_key_authentication_failed', { reason: 'invalid_key' }, req);
      return ResponseUtils.unauthorized(res, 'Invalid API key');
    }

    const { userId, permissions, expiresAt } = keyData;

    // Check if key is expired
    if (expiresAt && new Date() > new Date(expiresAt)) {
      logger.logSecurity('api_key_authentication_failed', { reason: 'expired_key' }, req);
      return ResponseUtils.unauthorized(res, 'API key has expired');
    }

    // Get user associated with API key
    const user = await User.findById(userId).select('-password');
    if (!user || !user.isActive) {
      logger.logSecurity('api_key_authentication_failed', { reason: 'user_invalid' }, req);
      return ResponseUtils.unauthorized(res, 'Invalid API key user');
    }

    req.user = user;
    req.apiKeyPermissions = permissions;

    logger.logAuth('api_key_verified', userId, { permissions });
    next();
  } catch (error) {
    logger.logError(error, req);
    return ResponseUtils.error(res, 'API key authentication failed');
  }
};

/**
 * Rate Limiting by User
 * Additional rate limiting based on authenticated user
 */
const userRateLimit = (maxRequests = 1000, windowMs = 3600000) => {
  return async (req, res, next) => {
    if (!req.user) {
      return next();
    }

    try {
      const userId = req.user._id.toString();
      const key = `user_rate_limit:${userId}`;
      const currentTime = Date.now();
      const windowStart = currentTime - windowMs;

      // Get current request count
      const requestCount = await redisClient.incr(key);
      
      if (requestCount === 1) {
        // Set expiration for the key
        await redisClient.expire(key, Math.ceil(windowMs / 1000));
      }

      if (requestCount > maxRequests) {
        logger.logSecurity('user_rate_limit_exceeded', {
          userId,
          requestCount,
          limit: maxRequests,
        }, req);
        return ResponseUtils.tooManyRequests(res, 'User rate limit exceeded');
      }

      next();
    } catch (error) {
      logger.logError(error, req);
      next(); // Don't block requests on rate limit errors
    }
  };
};

module.exports = {
  authenticate,
  optionalAuth,
  authorize,
  checkOwnership,
  checkSessionOwnership,
  authenticateApiKey,
  userRateLimit,
};