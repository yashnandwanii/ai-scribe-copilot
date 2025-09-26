const express = require('express');
const { authenticate, authorize, userRateLimit } = require('../middleware/auth');
const { validate, userValidation } = require('../utils/validation');
const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');
const User = require('../models/User');
const SecurityUtils = require('../utils/security');
const { asyncErrorHandler } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user (doctor)
 * @access  Public
 */
router.post('/register', 
  validate(userValidation.register),
  asyncErrorHandler(async (req, res) => {
    const { name, email, password, phone, specialty, licenseNumber, hospitalAffiliation } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.logSecurity('registration_attempt_duplicate_email', { email }, req);
      return ResponseUtils.error(res, 'User with this email already exists', 409);
    }

    // Check license number uniqueness if provided
    if (licenseNumber) {
      const existingLicense = await User.findOne({ licenseNumber });
      if (existingLicense) {
        return ResponseUtils.error(res, 'This license number is already registered', 409);
      }
    }

    // Create new user
    const userData = {
      name,
      email,
      password,
      phone,
      specialty,
      licenseNumber,
      hospitalAffiliation,
      role: 'doctor' // Default role
    };

    const user = new User(userData);
    await user.save();

    // Generate email verification token
    const verificationToken = user.createEmailVerificationToken();
    await user.save();

    // Generate JWT token
    const token = user.generateAuthToken();
    const refreshToken = user.generateRefreshToken();

    // Store refresh token in Redis
    await redisClient.setex(
      `refresh_token:${user._id}`,
      30 * 24 * 60 * 60, // 30 days
      refreshToken
    );

    // Log registration
    logger.logAuth('user_registered', user._id, {
      email: user.email,
      role: user.role
    });

    // Set HTTP-only cookie for token
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    ResponseUtils.created(res, {
      user: user.toSafeObject(),
      token,
      refreshToken,
      verificationRequired: true
    }, 'User registered successfully');
  })
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login',
  userRateLimit(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
  validate(userValidation.login),
  asyncErrorHandler(async (req, res) => {
    const { email, password, rememberMe } = req.body;

    try {
      // Find user by credentials (includes password checking and login attempt handling)
      const user = await User.findByCredentials(email, password);

      // Generate tokens
      const token = user.generateAuthToken();
      const refreshToken = user.generateRefreshToken();

      // Set token expiration based on rememberMe
      const tokenExpiry = rememberMe ? 30 * 24 * 60 * 60 : 7 * 24 * 60 * 60; // 30 days or 7 days

      // Store refresh token in Redis
      await redisClient.setex(
        `refresh_token:${user._id}`,
        tokenExpiry,
        refreshToken
      );

      // Log successful login
      logger.logAuth('user_login_success', user._id, {
        email: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Set HTTP-only cookie for token
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: tokenExpiry * 1000
      });

      ResponseUtils.success(res, {
        user: user.toSafeObject(),
        token,
        refreshToken,
        expiresIn: tokenExpiry
      }, 'Login successful');

    } catch (error) {
      logger.logSecurity('login_failed', {
        email,
        error: error.message,
        ip: req.ip
      }, req);

      ResponseUtils.unauthorized(res, error.message);
    }
  })
);

/**
 * @route   POST /api/v1/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh',
  asyncErrorHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return ResponseUtils.unauthorized(res, 'Refresh token required');
    }

    try {
      // Verify refresh token
      const decoded = SecurityUtils.verifyToken(refreshToken, true);

      // Check if refresh token exists in Redis
      const storedToken = await redisClient.get(`refresh_token:${decoded.userId}`);
      if (!storedToken || storedToken !== refreshToken) {
        logger.logSecurity('invalid_refresh_token', { userId: decoded.userId }, req);
        return ResponseUtils.unauthorized(res, 'Invalid refresh token');
      }

      // Find user
      const user = await User.findById(decoded.userId);
      if (!user || !user.isActive) {
        return ResponseUtils.unauthorized(res, 'User not found or inactive');
      }

      // Generate new tokens
      const newToken = user.generateAuthToken();
      const newRefreshToken = user.generateRefreshToken();

      // Update refresh token in Redis
      await redisClient.setex(
        `refresh_token:${user._id}`,
        30 * 24 * 60 * 60, // 30 days
        newRefreshToken
      );

      // Delete old refresh token
      await redisClient.del(`refresh_token:${decoded.userId}`);

      logger.logAuth('token_refreshed', user._id);

      ResponseUtils.success(res, {
        token: newToken,
        refreshToken: newRefreshToken,
        user: user.toSafeObject()
      }, 'Token refreshed successfully');

    } catch (error) {
      logger.logSecurity('refresh_token_failed', { error: error.message }, req);
      ResponseUtils.unauthorized(res, 'Invalid refresh token');
    }
  })
);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const token = req.token;
    const userId = req.user._id;

    // Add token to blacklist
    const decoded = SecurityUtils.verifyToken(token);
    const expiryTime = decoded.exp * 1000 - Date.now();
    
    if (expiryTime > 0) {
      await redisClient.setex(`blacklist:${token}`, Math.ceil(expiryTime / 1000), 'true');
    }

    // Remove refresh token
    await redisClient.del(`refresh_token:${userId}`);

    // Clear cookie
    res.clearCookie('token');

    logger.logAuth('user_logout', userId);

    ResponseUtils.success(res, null, 'Logout successful');
  })
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Send password reset email
 * @access  Public
 */
router.post('/forgot-password',
  userRateLimit(5, 60 * 60 * 1000), // 5 attempts per hour
  validate(userValidation.forgotPassword),
  asyncErrorHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email, isActive: true });
    
    if (!user) {
      // Don't reveal if email exists or not
      return ResponseUtils.success(res, null, 'If the email exists, a reset link has been sent');
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save();

    // TODO: Send email with reset token
    // For now, we'll just log it (in development)
    if (process.env.NODE_ENV === 'development') {
      logger.info(`Password reset token for ${email}: ${resetToken}`);
    }

    logger.logAuth('password_reset_requested', user._id, { email });

    ResponseUtils.success(res, null, 'If the email exists, a reset link has been sent');
  })
);

/**
 * @route   POST /api/v1/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password',
  validate(userValidation.resetPassword),
  asyncErrorHandler(async (req, res) => {
    const { token, password } = req.body;

    // Find user by reset token
    const user = await User.findByPasswordResetToken(token);
    if (!user) {
      return ResponseUtils.error(res, 'Invalid or expired reset token', 400);
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = Date.now();

    await user.save();

    logger.logAuth('password_reset_completed', user._id);

    ResponseUtils.success(res, null, 'Password reset successful');
  })
);

/**
 * @route   POST /api/v1/auth/change-password
 * @desc    Change password for authenticated user
 * @access  Private
 */
router.post('/change-password',
  authenticate,
  validate(userValidation.changePassword),
  asyncErrorHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id).select('+password');

    // Verify current password
    const isCurrentPasswordValid = await user.checkPassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return ResponseUtils.error(res, 'Current password is incorrect', 400);
    }

    // Update password
    user.password = newPassword;
    user.passwordChangedAt = Date.now();
    await user.save();

    // Invalidate all existing tokens by updating passwordChangedAt
    // Remove all refresh tokens for this user
    await redisClient.del(`refresh_token:${user._id}`);

    logger.logAuth('password_changed', user._id);

    ResponseUtils.success(res, null, 'Password changed successfully');
  })
);

/**
 * @route   GET /api/v1/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    ResponseUtils.success(res, user.toSafeObject(), 'Profile retrieved successfully');
  })
);

/**
 * @route   PUT /api/v1/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile',
  authenticate,
  validate(userValidation.updateProfile),
  asyncErrorHandler(async (req, res) => {
    const allowedUpdates = ['name', 'phone', 'specialty', 'licenseNumber', 'hospitalAffiliation'];
    const updates = {};

    // Filter allowed updates
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Check license number uniqueness if being updated
    if (updates.licenseNumber && updates.licenseNumber !== req.user.licenseNumber) {
      const existingLicense = await User.findOne({ 
        licenseNumber: updates.licenseNumber,
        _id: { $ne: req.user._id }
      });
      if (existingLicense) {
        return ResponseUtils.error(res, 'This license number is already registered', 409);
      }
    }

    updates.updatedBy = req.user._id;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    );

    logger.logAuth('profile_updated', user._id, { updatedFields: Object.keys(updates) });

    ResponseUtils.success(res, user.toSafeObject(), 'Profile updated successfully');
  })
);

/**
 * @route   POST /api/v1/auth/verify-email/:token
 * @desc    Verify email address
 * @access  Public
 */
router.post('/verify-email/:token',
  asyncErrorHandler(async (req, res) => {
    const { token } = req.params;

    const user = await User.findByVerificationToken(token);
    if (!user) {
      return ResponseUtils.error(res, 'Invalid or expired verification token', 400);
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    logger.logAuth('email_verified', user._id);

    ResponseUtils.success(res, null, 'Email verified successfully');
  })
);

/**
 * @route   POST /api/v1/auth/resend-verification
 * @desc    Resend email verification
 * @access  Private
 */
router.post('/resend-verification',
  authenticate,
  userRateLimit(3, 60 * 60 * 1000), // 3 attempts per hour
  asyncErrorHandler(async (req, res) => {
    const user = req.user;

    if (user.isEmailVerified) {
      return ResponseUtils.error(res, 'Email is already verified', 400);
    }

    const verificationToken = user.createEmailVerificationToken();
    await user.save();

    // TODO: Send verification email
    if (process.env.NODE_ENV === 'development') {
      logger.info(`Email verification token for ${user.email}: ${verificationToken}`);
    }

    logger.logAuth('verification_email_resent', user._id);

    ResponseUtils.success(res, null, 'Verification email sent');
  })
);

/**
 * @route   DELETE /api/v1/auth/account
 * @desc    Delete user account
 * @access  Private
 */
router.delete('/account',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const user = req.user;

    // Instead of hard delete, deactivate the account
    user.isActive = false;
    user.email = `deleted_${Date.now()}_${user.email}`;
    await user.save();

    // Remove all refresh tokens
    await redisClient.del(`refresh_token:${user._id}`);

    // Add current token to blacklist
    const token = req.token;
    const decoded = SecurityUtils.verifyToken(token);
    const expiryTime = decoded.exp * 1000 - Date.now();
    
    if (expiryTime > 0) {
      await redisClient.setex(`blacklist:${token}`, Math.ceil(expiryTime / 1000), 'true');
    }

    logger.logAuth('account_deleted', user._id);

    ResponseUtils.success(res, null, 'Account deleted successfully');
  })
);

module.exports = router;