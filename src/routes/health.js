const express = require('express');
const { authenticate } = require('../middleware/auth');
const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');
const mongoose = require('mongoose');
const { asyncErrorHandler } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * @route   GET /api/v1/health
 * @desc    Basic health check
 * @access  Public
 */
router.get('/',
  asyncErrorHandler(async (req, res) => {
    const healthCheck = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
      node_version: process.version
    };

    ResponseUtils.success(res, healthCheck, 'Service is healthy');
  })
);

/**
 * @route   GET /api/v1/health/detailed
 * @desc    Detailed health check with dependencies
 * @access  Private (Admin only)
 */
router.get('/detailed',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const startTime = Date.now();
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
      node_version: process.version,
      memory: process.memoryUsage(),
      pid: process.pid,
      checks: {}
    };

    // Check MongoDB connectivity
    try {
      const mongoStart = Date.now();
      await mongoose.connection.db.admin().ping();
      healthStatus.checks.mongodb = {
        status: 'healthy',
        responseTime: Date.now() - mongoStart,
        connection: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        host: mongoose.connection.host,
        port: mongoose.connection.port,
        database: mongoose.connection.name
      };
    } catch (error) {
      healthStatus.status = 'unhealthy';
      healthStatus.checks.mongodb = {
        status: 'unhealthy',
        error: error.message
      };
    }

    // Redis removed - not using caching layer

    // AWS S3 removed - using local file storage

    // System metrics
    const loadAverage = require('os').loadavg();
    const totalMemory = require('os').totalmem();
    const freeMemory = require('os').freemem();

    healthStatus.system = {
      platform: process.platform,
      arch: process.arch,
      loadAverage: {
        '1m': loadAverage[0],
        '5m': loadAverage[1],
        '15m': loadAverage[2]
      },
      memory: {
        total: totalMemory,
        free: freeMemory,
        used: totalMemory - freeMemory,
        usagePercentage: Math.round(((totalMemory - freeMemory) / totalMemory) * 100)
      },
      disk: await getDiskUsage()
    };

    healthStatus.responseTime = Date.now() - startTime;

    // Log health check if unhealthy
    if (healthStatus.status === 'unhealthy') {
      logger.warn('Health check failed', healthStatus);
    }

    const statusCode = healthStatus.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json({
      success: healthStatus.status === 'healthy',
      data: healthStatus,
      message: `Service is ${healthStatus.status}`
    });
  })
);

/**
 * @route   GET /api/v1/health/liveness
 * @desc    Kubernetes liveness probe
 * @access  Public
 */
router.get('/liveness',
  asyncErrorHandler(async (req, res) => {
    // Simple check that the process is running
    res.status(200).json({
      status: 'alive',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  })
);

/**
 * @route   GET /api/v1/health/readiness
 * @desc    Kubernetes readiness probe
 * @access  Public
 */
router.get('/readiness',
  asyncErrorHandler(async (req, res) => {
    let isReady = true;
    const checks = {};

    // Check MongoDB
    try {
      await mongoose.connection.db.admin().ping();
      checks.mongodb = 'ready';
    } catch (error) {
      isReady = false;
      checks.mongodb = 'not ready';
    }

    // Redis removed - not using caching layer

    const statusCode = isReady ? 200 : 503;
    res.status(statusCode).json({
      status: isReady ? 'ready' : 'not ready',
      timestamp: new Date().toISOString(),
      checks
    });
  })
);

/**
 * @route   GET /api/v1/health/metrics
 * @desc    Application metrics
 * @access  Private (Admin only)
 */
router.get('/metrics',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const User = require('../models/User');
    const Patient = require('../models/Patient');
    const Session = require('../models/Session');

    try {
      // Get database counts
      const [userCount, patientCount, sessionCount] = await Promise.all([
        User.countDocuments({ isActive: true }),
        Patient.countDocuments({ isActive: true }),
        Session.countDocuments({ isArchived: false })
      ]);

      // Get session statistics for the last 24 hours
      const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const recentSessions = await Session.countDocuments({
        createdAt: { $gte: last24Hours },
        isArchived: false
      });

      // Get memory usage
      const memoryUsage = process.memoryUsage();

      // Redis stats removed - not using caching layer

      const metrics = {
        timestamp: new Date().toISOString(),
        application: {
          uptime: process.uptime(),
          version: process.env.npm_package_version || '1.0.0',
          environment: process.env.NODE_ENV || 'development',
          nodeVersion: process.version
        },
        database: {
          users: userCount,
          patients: patientCount,
          sessions: sessionCount,
          recentSessions24h: recentSessions
        },
        memory: {
          rss: memoryUsage.rss,
          heapTotal: memoryUsage.heapTotal,
          heapUsed: memoryUsage.heapUsed,
          external: memoryUsage.external,
          arrayBuffers: memoryUsage.arrayBuffers
        },

        system: {
          platform: process.platform,
          arch: process.arch,
          cpus: require('os').cpus().length,
          loadAverage: require('os').loadavg()
        }
      };

      ResponseUtils.success(res, metrics, 'Metrics retrieved successfully');
    } catch (error) {
      logger.error('Error retrieving metrics:', error);
      ResponseUtils.error(res, 'Failed to retrieve metrics');
    }
  })
);

/**
 * @route   POST /api/v1/health/log-test
 * @desc    Test logging system
 * @access  Private (Admin only)
 */
router.post('/log-test',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const { level = 'info', message = 'Test log message' } = req.body;

    const validLevels = ['error', 'warn', 'info', 'debug'];
    if (!validLevels.includes(level)) {
      return ResponseUtils.error(res, 'Invalid log level', 400);
    }

    const testData = {
      userId: req.user._id,
      timestamp: new Date().toISOString(),
      testMessage: message
    };

    // Log at specified level
    logger[level]('Health check log test', testData);

    ResponseUtils.success(res, {
      level,
      message,
      timestamp: new Date().toISOString()
    }, 'Log test completed successfully');
  })
);

/**
 * Helper function to get disk usage
 */
async function getDiskUsage() {
  try {
    const fs = require('fs').promises;
    const stats = await fs.stat('./');
    
    // This is a simplified disk usage check
    // In production, you might want to use a more sophisticated method
    return {
      available: true,
      path: process.cwd()
    };
  } catch (error) {
    return {
      available: false,
      error: error.message
    };
  }
}

/**
 * @route   GET /api/v1/health/performance
 * @desc    Performance metrics and benchmarks
 * @access  Private (Admin only)
 */
router.get('/performance',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const startTime = process.hrtime.bigint();

    // Database performance test
    const dbStart = process.hrtime.bigint();
    try {
      await mongoose.connection.db.admin().ping();
      const dbTime = Number(process.hrtime.bigint() - dbStart) / 1000000; // Convert to milliseconds

      // Redis performance test
      const redisStart = process.hrtime.bigint();
      await redis.ping();
      const redisTime = Number(process.hrtime.bigint() - redisStart) / 1000000;

      // Memory allocation test
      const memStart = process.hrtime.bigint();
      const testArray = new Array(10000).fill('performance test');
      const memTime = Number(process.hrtime.bigint() - memStart) / 1000000;

      const totalTime = Number(process.hrtime.bigint() - startTime) / 1000000;

      const performance = {
        timestamp: new Date().toISOString(),
        tests: {
          database: {
            responseTime: dbTime,
            status: 'healthy'
          },
          redis: {
            responseTime: redisTime,
            status: 'healthy'
          },
          memory: {
            allocationTime: memTime,
            status: 'healthy'
          }
        },
        totalResponseTime: totalTime,
        recommendations: []
      };

      // Add performance recommendations
      if (dbTime > 100) {
        performance.recommendations.push('Database response time is high. Consider optimization.');
      }
      if (redisTime > 50) {
        performance.recommendations.push('Redis response time is high. Check connection.');
      }
      if (process.memoryUsage().heapUsed > 500 * 1024 * 1024) {
        performance.recommendations.push('High memory usage detected. Consider optimization.');
      }

      ResponseUtils.success(res, performance, 'Performance metrics retrieved successfully');
    } catch (error) {
      logger.error('Performance test failed:', error);
      ResponseUtils.error(res, 'Performance test failed');
    }
  })
);

module.exports = router;