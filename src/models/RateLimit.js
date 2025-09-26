const mongoose = require('mongoose');

const rateLimitSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  count: {
    type: Number,
    required: true,
    default: 1
  },
  windowStart: {
    type: Date,
    required: true,
    default: Date.now,
    index: { expireAfterSeconds: 900 } // Auto-delete after 15 minutes
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 }
  }
});

// Compound index for efficient queries
rateLimitSchema.index({ key: 1, windowStart: 1 });

// Static method to increment rate limit counter
rateLimitSchema.statics.incrementLimit = async function(key, windowMs = 900000, maxRequests = 100) {
  try {
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowMs);
    const expiresAt = new Date(now.getTime() + windowMs);
    
    // Try to find existing rate limit record within the window
    let rateLimit = await this.findOne({
      key,
      windowStart: { $gte: windowStart }
    });
    
    if (rateLimit) {
      // Increment existing counter
      rateLimit.count += 1;
      rateLimit.expiresAt = expiresAt;
      await rateLimit.save();
      
      return {
        count: rateLimit.count,
        remaining: Math.max(0, maxRequests - rateLimit.count),
        resetTime: new Date(rateLimit.windowStart.getTime() + windowMs),
        exceeded: rateLimit.count > maxRequests
      };
    } else {
      // Create new rate limit record
      rateLimit = await this.create({
        key,
        count: 1,
        windowStart: now,
        expiresAt
      });
      
      return {
        count: 1,
        remaining: maxRequests - 1,
        resetTime: new Date(now.getTime() + windowMs),
        exceeded: false
      };
    }
  } catch (error) {
    // If database error, allow request to proceed
    return {
      count: 0,
      remaining: maxRequests,
      resetTime: new Date(Date.now() + windowMs),
      exceeded: false
    };
  }
};

// Static method to check current rate limit status
rateLimitSchema.statics.checkLimit = async function(key, windowMs = 900000, maxRequests = 100) {
  try {
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowMs);
    
    const rateLimit = await this.findOne({
      key,
      windowStart: { $gte: windowStart }
    });
    
    if (rateLimit) {
      return {
        count: rateLimit.count,
        remaining: Math.max(0, maxRequests - rateLimit.count),
        resetTime: new Date(rateLimit.windowStart.getTime() + windowMs),
        exceeded: rateLimit.count >= maxRequests
      };
    } else {
      return {
        count: 0,
        remaining: maxRequests,
        resetTime: new Date(now.getTime() + windowMs),
        exceeded: false
      };
    }
  } catch (error) {
    // If database error, allow request to proceed
    return {
      count: 0,
      remaining: maxRequests,
      resetTime: new Date(Date.now() + windowMs),
      exceeded: false
    };
  }
};

// Static method to reset rate limit for a key
rateLimitSchema.statics.resetLimit = async function(key) {
  try {
    const result = await this.deleteMany({ key });
    return result.deletedCount;
  } catch (error) {
    return 0;
  }
};

// Static method to clean expired rate limits
rateLimitSchema.statics.cleanExpiredLimits = async function() {
  try {
    const result = await this.deleteMany({
      expiresAt: { $lt: new Date() }
    });
    return result.deletedCount;
  } catch (error) {
    throw error;
  }
};

module.exports = mongoose.model('RateLimit', rateLimitSchema);