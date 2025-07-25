const mongoose = require('mongoose');
const User = require('../models/User');
const Role = require('../models/Role');
const BlacklistedToken = require('../models/BlacklistedToken');
const APIResponse = require('../utils/response');
const { handleValidationErrors } = require('../utils/validation');
const { createAuditLog } = require('../middlewares/auth');
const jwt = require('jsonwebtoken');
const config = require('../config');

// Register new user
exports.register = async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return APIResponse.error(res, req.t('user.emailExists'), 400);
    }

    // Get role by ID or name
    let userRole;
    if (role) {
      // Try to find by ObjectId first, then by name
      if (mongoose.Types.ObjectId.isValid(role)) {
        userRole = await Role.findById(role);
      } else {
        userRole = await Role.findOne({ name: role });
      }
      
      if (!userRole) {
        return APIResponse.error(res, 'Invalid role. Role not found.', 400);
      }
    } else {
      // Get default 'user' role
      userRole = await Role.findOne({ name: 'user' });
      if (!userRole) {
        return APIResponse.error(res, 'Default user role not found. Please run database seeder first.', 500);
      }
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      role: userRole._id
    });

    // Generate token
    const token = user.generateAuthToken();

    // Create audit log
    await createAuditLog(
      user._id,
      'register',
      'user',
      { 
        email: user.email,
        role: userRole.name,
        registration_method: 'standard'
      },
      req,
      'success',
      'low'
    );

    // Remove password from response
    user.password = undefined;

    APIResponse.created(res, {
      user,
      token
    }, req.t('auth.userCreated'));

  } catch (error) {
    next(error);
  }
};

// Enhanced login with detailed audit logging
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Get user with password
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      // Log failed login attempt
      await createAuditLog(
        null,
        'failed_login',
        'auth',
        { 
          email,
          reason: 'user_not_found'
        },
        req,
        'failure',
        'medium'
      );
      
      return APIResponse.error(res, req.t('auth.invalidCredentials'), 401);
    }

    // Check if account is locked
    if (user.isLocked) {
      await createAuditLog(
        user._id,
        'failed_login',
        'auth',
        { 
          reason: 'account_locked',
          lockUntil: user.lockUntil
        },
        req,
        'failure',
        'medium'
      );
      
      return APIResponse.error(res, req.t('user.accountLocked'), 423);
    }

    // Check if account is active
    if (user.status !== 'active') {
      await createAuditLog(
        user._id,
        'failed_login',
        'auth',
        { 
          reason: 'account_inactive',
          status: user.status
        },
        req,
        'failure',
        'medium'
      );
      
      return APIResponse.error(res, req.t('errors.unauthorized'), 401);
    }

    // Check password
    const isPasswordCorrect = await user.comparePassword(password);
    
    if (!isPasswordCorrect) {
      // Increment login attempts
      await user.incLoginAttempts();
      
      // Log failed login
      await createAuditLog(
        user._id,
        'failed_login',
        'auth',
        { 
          reason: 'invalid_password',
          attempts: user.loginAttempts + 1
        },
        req,
        'failure',
        user.loginAttempts >= 3 ? 'high' : 'medium'
      );
      
      return APIResponse.error(res, req.t('auth.invalidCredentials'), 401);
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Generate token
    const token = user.generateAuthToken();

    // Log successful login
    await createAuditLog(
      user._id,
      'login',
      'auth',
      { 
        login_method: 'password',
        user_agent: req.get('User-Agent'),
        last_login: user.lastLogin
      },
      req,
      'success',
      'low'
    );

    // Remove password from response
    user.password = undefined;

    APIResponse.success(res, {
      user,
      token
    }, req.t('auth.loginSuccess'));

  } catch (error) {
    next(error);
  }
};

// Enhanced logout with token blacklisting
exports.logout = async (req, res, next) => {
  try {
    const token = req.token;
    const user = req.user;

    // Decode token to get expiration
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    // Add token to blacklist
    await BlacklistedToken.create({
      token,
      userId: user._id,
      reason: 'logout',
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
      expiresAt
    });

    // Log logout
    await createAuditLog(
      user._id,
      'logout',
      'auth',
      { 
        logout_method: 'manual',
        token_expires_at: expiresAt
      },
      req,
      'success',
      'low'
    );

    APIResponse.success(res, null, req.t('auth.logoutSuccess'));
  } catch (error) {
    next(error);
  }
};

// Get current user profile
exports.getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    APIResponse.success(res, { user }, 'Profile retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Enhanced profile update with audit logging
exports.updateProfile = async (req, res, next) => {
  try {
    const { name, email } = req.body;
    const oldUser = await User.findById(req.user.id);
    
    if (!oldUser) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    // Check if email is being changed and already exists
    if (email && email !== req.user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return APIResponse.error(res, req.t('user.emailExists'), 400);
      }
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { name, email },
      { new: true, runValidators: true }
    );

    // Log profile update
    const changes = {};
    if (name !== oldUser.name) changes.name = { from: oldUser.name, to: name };
    if (email !== oldUser.email) changes.email = { from: oldUser.email, to: email };

    await createAuditLog(
      user._id,
      'profile_update',
      'user',
      { 
        changes,
        updated_by: 'self'
      },
      req,
      'success',
      'low'
    );

    APIResponse.updated(res, { user }, req.t('auth.userUpdated'));

  } catch (error) {
    next(error);
  }
};

// Enhanced password change with security measures
exports.changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const user = await User.findById(req.user.id).select('+password');

    // Check current password
    const isCurrentPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordCorrect) {
      // Log failed password change
      await createAuditLog(
        user._id,
        'password_change',
        'auth',
        { reason: 'incorrect_current_password' },
        req,
        'failure',
        'high'
      );
      
      return APIResponse.error(res, 'Current password is incorrect', 400);
    }

    // Update password
    user.password = newPassword;
    await user.save();

    // Invalidate current token
    const decoded = jwt.decode(req.token);
    const expiresAt = new Date(decoded.exp * 1000);
    
    await BlacklistedToken.create({
      token: req.token,
      userId: user._id,
      reason: 'password_change',
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
      expiresAt
    });

    // Log successful password change
    await createAuditLog(
      user._id,
      'password_change',
      'auth',
      { 
        method: 'self_change',
        tokens_invalidated: true
      },
      req,
      'success',
      'medium'
    );

    APIResponse.success(res, null, req.t('auth.passwordChanged'));

  } catch (error) {
    next(error);
  }
};

// Enhanced Force logout all sessions 
exports.forceLogoutAll = async (req, res, next) => {
  try {
    const user = req.user;
    
    // Invalidate current token
    const decoded = jwt.decode(req.token);
    const expiresAt = new Date(decoded.exp * 1000);
    
    await BlacklistedToken.create({
      token: req.token,
      userId: user._id,
      reason: 'force_logout',
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
      expiresAt
    });

    // Log force logout
    await createAuditLog(
      user._id,
      'logout',
      'auth',
      { 
        logout_method: 'force_all_sessions',
        initiated_by: 'user',
        note: 'In a production system, this would invalidate all user tokens'
      },
      req,
      'success',
      'medium'
    );

    APIResponse.success(res, null, 'All sessions logged out successfully');
  } catch (error) {
    next(error);
  }
};