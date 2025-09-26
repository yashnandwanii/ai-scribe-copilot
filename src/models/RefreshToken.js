const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true, // One refresh token per user
    index: true
  },
  token: {
    type: String,
    required: true,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 } // Auto-delete expired tokens
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastUsedAt: {
    type: Date,
    default: Date.now
  },
  deviceInfo: {
    userAgent: String,
    ipAddress: String,
    deviceType: String
  }
});

// Index for efficient queries
refreshTokenSchema.index({ userId: 1, expiresAt: 1 });
refreshTokenSchema.index({ token: 1, expiresAt: 1 });

// Static method to store refresh token
refreshTokenSchema.statics.storeToken = async function(userId, token, expiresIn, deviceInfo = {}) {
  try {
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    
    // Use upsert to replace existing token for the user
    const result = await this.findOneAndUpdate(
      { userId },
      {
        token,
        expiresAt,
        lastUsedAt: new Date(),
        deviceInfo,
        createdAt: new Date()
      },
      { 
        upsert: true, 
        new: true,
        setDefaultsOnInsert: true
      }
    );
    
    return result;
  } catch (error) {
    throw error;
  }
};

// Static method to get refresh token
refreshTokenSchema.statics.getToken = async function(userId) {
  try {
    const tokenDoc = await this.findOne({
      userId,
      expiresAt: { $gt: new Date() }
    });
    
    if (tokenDoc) {
      // Update last used timestamp
      tokenDoc.lastUsedAt = new Date();
      await tokenDoc.save();
      return tokenDoc.token;
    }
    
    return null;
  } catch (error) {
    return null;
  }
};

// Static method to verify and get refresh token
refreshTokenSchema.statics.verifyToken = async function(token) {
  try {
    const tokenDoc = await this.findOne({
      token,
      expiresAt: { $gt: new Date() }
    }).populate('userId');
    
    if (tokenDoc) {
      // Update last used timestamp
      tokenDoc.lastUsedAt = new Date();
      await tokenDoc.save();
      return tokenDoc;
    }
    
    return null;
  } catch (error) {
    return null;
  }
};

// Static method to delete refresh token
refreshTokenSchema.statics.deleteToken = async function(userId) {
  try {
    const result = await this.deleteOne({ userId });
    return result.deletedCount > 0;
  } catch (error) {
    return false;
  }
};

// Static method to delete token by token value
refreshTokenSchema.statics.deleteByToken = async function(token) {
  try {
    const result = await this.deleteOne({ token });
    return result.deletedCount > 0;
  } catch (error) {
    return false;
  }
};

// Static method to clean expired tokens
refreshTokenSchema.statics.cleanExpiredTokens = async function() {
  try {
    const result = await this.deleteMany({
      expiresAt: { $lt: new Date() }
    });
    return result.deletedCount;
  } catch (error) {
    throw error;
  }
};

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);