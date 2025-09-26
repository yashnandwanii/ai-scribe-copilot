const mongoose = require('mongoose');

const tokenBlacklistSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 } // Auto-delete expired tokens
  },
  reason: {
    type: String,
    enum: ['logout', 'password_change', 'account_deactivation', 'manual'],
    default: 'logout'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient queries
tokenBlacklistSchema.index({ token: 1, expiresAt: 1 });

// Static method to blacklist a token
tokenBlacklistSchema.statics.blacklistToken = async function(token, userId, expiresAt, reason = 'logout') {
  try {
    await this.create({
      token,
      userId,
      expiresAt,
      reason
    });
    return true;
  } catch (error) {
    if (error.code === 11000) {
      // Token already blacklisted
      return true;
    }
    throw error;
  }
};

// Static method to check if token is blacklisted
tokenBlacklistSchema.statics.isBlacklisted = async function(token) {
  try {
    const blacklistedToken = await this.findOne({
      token,
      expiresAt: { $gt: new Date() }
    });
    return !!blacklistedToken;
  } catch (error) {
    // If database error, assume token is valid to avoid blocking users
    return false;
  }
};

// Static method to clean expired tokens (optional cleanup)
tokenBlacklistSchema.statics.cleanExpiredTokens = async function() {
  try {
    const result = await this.deleteMany({
      expiresAt: { $lt: new Date() }
    });
    return result.deletedCount;
  } catch (error) {
    throw error;
  }
};

module.exports = mongoose.model('TokenBlacklist', tokenBlacklistSchema);