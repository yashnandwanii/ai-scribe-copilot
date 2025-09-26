const { createClient } = require('redis');
const logger = require('../utils/logger');

class RedisConfig {
  constructor() {
    this.client = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      // Create Redis client with flexible configuration
      const redisConfig = this.getRedisConfig();
      
      this.client = createClient(redisConfig);

      // Event listeners
      this.client.on('error', (err) => {
        logger.error('Redis Client Error:', err);
        this.isConnected = false;
      });

      this.client.on('connect', () => {
        logger.info('Redis client connected');
        this.isConnected = true;
      });

      this.client.on('ready', () => {
        logger.info('Redis client ready');
        this.isConnected = true;
      });

      this.client.on('end', () => {
        logger.info('Redis client disconnected');
        this.isConnected = false;
      });

      // Connect to Redis
      await this.client.connect();
      
      // Test connection
      await this.client.ping();
      logger.info('Redis connection established successfully');
      
      return this.client;
    } catch (error) {
      logger.error('Failed to connect to Redis:', error);
      throw error;
    }
  }

  getRedisConfig() {
    // Priority 1: Individual Redis config (for Redis Cloud)
    if (process.env.REDIS_HOST && process.env.REDIS_PORT) {
      return {
        username: process.env.REDIS_USERNAME || 'default',
        password: process.env.REDIS_PASSWORD || undefined,
        socket: {
          host: process.env.REDIS_HOST,
          port: parseInt(process.env.REDIS_PORT, 10),
          connectTimeout: 10000,
          commandTimeout: 5000,
          lazyConnect: true
        }
      };
    }

    // Priority 2: REDIS_URL (for backwards compatibility)
    if (process.env.REDIS_URL && process.env.REDIS_URL !== 'redis://localhost:6379') {
      return {
        url: process.env.REDIS_URL,
        socket: {
          connectTimeout: 10000,
          commandTimeout: 5000,
          lazyConnect: true
        }
      };
    }

    // Priority 3: Default local Redis configuration
    return {
      socket: {
        host: 'localhost',
        port: 6379,
        connectTimeout: 5000,
        commandTimeout: 3000
      }
    };
  }

  async disconnect() {
    if (this.client && this.isConnected) {
      try {
        await this.client.disconnect();
        logger.info('Redis client disconnected successfully');
      } catch (error) {
        logger.error('Error disconnecting Redis client:', error);
      }
    }
  }

  getClient() {
    if (!this.client || !this.isConnected) {
      throw new Error('Redis client is not connected');
    }
    return this.client;
  }

  async healthCheck() {
    try {
      if (!this.client || !this.isConnected) {
        return { status: 'disconnected', error: 'Client not connected' };
      }
      
      const startTime = Date.now();
      await this.client.ping();
      const responseTime = Date.now() - startTime;
      
      return {
        status: 'connected',
        responseTime: `${responseTime}ms`,
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message
      };
    }
  }

  // Cache operations with error handling
  async set(key, value, options = {}) {
    try {
      const client = this.getClient();
      const serializedValue = typeof value === 'object' ? JSON.stringify(value) : value;
      
      if (options.ttl) {
        return await client.setEx(key, options.ttl, serializedValue);
      }
      
      return await client.set(key, serializedValue);
    } catch (error) {
      logger.error('Redis SET error:', error);
      throw error;
    }
  }

  async get(key) {
    try {
      const client = this.getClient();
      const value = await client.get(key);
      
      if (!value) return null;
      
      // Try to parse JSON, return as string if parsing fails
      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    } catch (error) {
      logger.error('Redis GET error:', error);
      throw error;
    }
  }

  async del(key) {
    try {
      const client = this.getClient();
      return await client.del(key);
    } catch (error) {
      logger.error('Redis DEL error:', error);
      throw error;
    }
  }

  async exists(key) {
    try {
      const client = this.getClient();
      return await client.exists(key);
    } catch (error) {
      logger.error('Redis EXISTS error:', error);
      throw error;
    }
  }

  async expire(key, seconds) {
    try {
      const client = this.getClient();
      return await client.expire(key, seconds);
    } catch (error) {
      logger.error('Redis EXPIRE error:', error);
      throw error;
    }
  }

  async flushAll() {
    try {
      const client = this.getClient();
      return await client.flushAll();
    } catch (error) {
      logger.error('Redis FLUSHALL error:', error);
      throw error;
    }
  }
}

// Create singleton instance
const redisConfig = new RedisConfig();

module.exports = redisConfig;