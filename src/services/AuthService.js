const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');
const BlacklistedToken = require('../models/BlacklistedToken');
const BaseService = require('./BaseService');
const config = require('../config');

/**
 * Authentication Service
 * Handles all authentication-related business logic
 */
class AuthService extends BaseService {
  constructor() {
    super(User);
  }

  // Register new user
  async register(userData, req) {
    const { name, email, password, role } = userData;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // Resolve role
    const userRole = await this.resolveRole(role);
    if (!userRole) {
      throw new Error('Invalid role. Role not found.');
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      role: userRole._id
    });

    // Generate token
    const token = this.generateToken(user);

    // Return user without password
    const userResponse = user.toJSON();
    delete userResponse.password;

    return {
      user: userResponse,
      token,
      role: userRole
    };
  }

  // Login user
  async login(credentials, req) {
    const { email, password } = credentials;

    // Get user with password
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      const error = new Error('Invalid credentials');
      error.code = 'USER_NOT_FOUND';
      error.auditData = { email, reason: 'user_not_found' };
      throw error;
    }

    // Check account status
    await this.validateUserAccount(user);

    // Verify password
    const isPasswordCorrect = await user.comparePassword(password);
    
    if (!isPasswordCorrect) {
      // Increment login attempts
      await user.incLoginAttempts();
      
      const error = new Error('Invalid credentials');
      error.code = 'INVALID_PASSWORD';
      error.auditData = { 
        userId: user._id,
        reason: 'invalid_password',
        attempts: user.loginAttempts + 1
      };
      throw error;
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Generate token
    const token = this.generateToken(user);

    // Return user without password
    const userResponse = user.toJSON();
    delete userResponse.password;

    return {
      user: userResponse,
      token,
      lastLogin: user.lastLogin
    };
  }

  // Logout user
  async logout(token, userId, req) {
    // Decode token to get expiration
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    // Add token to blacklist
    await BlacklistedToken.create({
      token,
      userId,
      reason: 'logout',
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
      expiresAt
    });

    return {
      message: 'Logged out successfully',
      tokenExpiration: expiresAt
    };
  }

  // Change user password
  async changePassword(userId, passwordData, currentToken, req) {
    const { currentPassword, newPassword } = passwordData;

    // Get user with password
    const user = await User.findById(userId).select('+password');
    if (!user) {
      throw new Error('User not found');
    }

    // Verify current password
    const isCurrentPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordCorrect) {
      const error = new Error('Current password is incorrect');
      error.code = 'INCORRECT_CURRENT_PASSWORD';
      error.auditData = { userId, reason: 'incorrect_current_password' };
      throw error;
    }

    // Update password
    user.password = newPassword;
    await user.save();

    // Blacklist current token
    await this.blacklistToken(currentToken, userId, 'password_change', req);

    return {
      message: 'Password changed successfully',
      tokenInvalidated: true
    };
  }

  // Update user profile
  async updateProfile(userId, profileData) {
    const { name, email } = profileData;
    
    // Get current user data
    const oldUser = await User.findById(userId);
    if (!oldUser) {
      throw new Error('User not found');
    }

    // Check email uniqueness if being changed
    if (email && email !== oldUser.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        throw new Error('Email already exists');
      }
    }

    // Update user
    const user = await User.findByIdAndUpdate(
      userId,
      { name, email },
      { new: true, runValidators: true }
    );

    // Track changes
    const changes = {};
    if (name !== oldUser.name) changes.name = { from: oldUser.name, to: name };
    if (email !== oldUser.email) changes.email = { from: oldUser.email, to: email };

    return {
      user: user.toJSON(),
      changes
    };
  }

  // Check if token is blacklisted
  async isTokenBlacklisted(token) {
    const blacklistedToken = await BlacklistedToken.findOne({ token });
    return !!blacklistedToken;
  }

  // Private methods
  
  // Resolve user role by ID or name
  async resolveRole(role) {
    if (!role) {
      // Get default 'user' role
      return await Role.findOne({ name: 'user' });
    }

    // Try to find by ObjectId first, then by name
    if (mongoose.Types.ObjectId.isValid(role)) {
      return await Role.findById(role);
    } else {
      return await Role.findOne({ name: role });
    }
  }

  // Validate user account status
  async validateUserAccount(user) {
    // Check if account is locked
    if (user.isLocked) {
      const error = new Error('Account temporarily locked');
      error.code = 'ACCOUNT_LOCKED';
      error.auditData = { 
        userId: user._id,
        reason: 'account_locked',
        lockUntil: user.lockUntil
      };
      throw error;
    }

    // Check if account is active
    if (user.status !== 'active') {
      const error = new Error('Account is not active');
      error.code = 'ACCOUNT_INACTIVE';
      error.auditData = { 
        userId: user._id,
        reason: 'account_inactive',
        status: user.status
      };
      throw error;
    }
  }

  // Generate JWT token
  generateToken(user) {
    return jwt.sign(
      { 
        id: user._id, 
        email: user.email,
        role: user.role.name,
        permissions: user.allPermissions
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
  }

  // Blacklist token
  async blacklistToken(token, userId, reason, req) {
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);
    
    await BlacklistedToken.create({
      token,
      userId,
      reason,
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
      expiresAt
    });
  }
}

module.exports = AuthService;