const mongoose = require('mongoose');
const logger = require('../utils/logger');

// Test database connection and models
async function testDatabaseConnection() {
  try {
    // Test basic connection
    await mongoose.connection.db.admin().ping();
    logger.info('MongoDB connection test: SUCCESS');
    
    // Test our new models
    const TokenBlacklist = require('../models/TokenBlacklist');
    const RefreshToken = require('../models/RefreshToken');
    const RateLimit = require('../models/RateLimit');
    
    logger.info('All authentication models loaded successfully');
    
    return true;
  } catch (error) {
    logger.error('Database connection test failed:', error);
    return false;
  }
}

module.exports = {
  testDatabaseConnection
};