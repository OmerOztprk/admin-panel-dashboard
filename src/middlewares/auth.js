const jwt = require('jsonwebtoken');
const User = require('../models/User');
const BlacklistedToken = require('../models/BlacklistedToken');
const AuditLog = require('../models/AuditLog');
const config = require('../config');

// Audit logging helper
const createAuditLog = async (userId, action, resource, details = {}, req, status = 'success', severity = 'low') => {
  try {
    await AuditLog.create({
      userId,
      action,
      resource,
      resourceId: details.resourceId || null,
      details,
      ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      status,
      severity
    });
  } catch (error) {
    console.error('Audit log creation failed:', error.message);
  }
};

// Enhanced protect middleware
exports.protect = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        status: 'error',
        message: req.t('errors.unauthorized')
      });
    }

    // Check if token is blacklisted
    const blacklistedToken = await BlacklistedToken.findOne({ token });
    if (blacklistedToken) {
      return res.status(401).json({
        status: 'error',
        message: 'Token has been invalidated',
        code: 'TOKEN_BLACKLISTED'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, config.jwt.secret);

    // Get user from token with populated roles
    const user = await User.findById(decoded.id);
    if (!user) {
      // Log suspicious activity
      await createAuditLog(
        decoded.id, 
        'failed_login', 
        'auth',
        { reason: 'user_not_found', token_payload: decoded },
        req,
        'failure',
        'high'
      );
      
      return res.status(401).json({
        status: 'error',
        message: req.t('errors.unauthorized')
      });
    }

    // Check if user is active
    if (user.status !== 'active') {
      await createAuditLog(
        user._id,
        'failed_login',
        'auth',
        { reason: 'account_inactive', status: user.status },
        req,
        'failure',
        'medium'
      );
      
      return res.status(401).json({
        status: 'error',
        message: req.t('errors.unauthorized')
      });
    }

    // Check if user is locked
    if (user.isLocked) {
      await createAuditLog(
        user._id,
        'failed_login',
        'auth',
        { reason: 'account_locked', lockUntil: user.lockUntil },
        req,
        'failure',
        'medium'
      );
      
      return res.status(423).json({
        status: 'error',
        message: 'Account temporarily locked due to too many failed login attempts',
        code: 'ACCOUNT_LOCKED'
      });
    }

    // Grant access to protected route
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    // Log JWT errors
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'error',
        message: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid token',
        code: 'TOKEN_INVALID'
      });
    }
    
    return res.status(401).json({
      status: 'error',
      message: req.t('errors.unauthorized')
    });
  }
};

// Permission-based access control
exports.requirePermission = (permission) => {
  return async (req, res, next) => {
    if (!req.user.hasPermission(permission)) {
      // Log unauthorized access attempt
      await createAuditLog(
        req.user._id,
        'access_denied',
        'auth',
        { 
          reason: 'insufficient_permissions',
          required_permission: permission,
          user_permissions: req.user.allPermissions,
          attempted_resource: req.originalUrl
        },
        req,
        'failure',
        'high'
      );
      
      return res.status(403).json({
        status: 'error',
        message: req.t('errors.forbidden'),
        code: 'INSUFFICIENT_PERMISSIONS',
        required: permission
      });
    }
    next();
  };
};

// Multiple permissions (user must have ANY of them)
exports.requireAnyPermission = (permissions) => {
  return async (req, res, next) => {
    if (!req.user.hasAnyPermission(permissions)) {
      await createAuditLog(
        req.user._id,
        'access_denied',
        'auth',
        { 
          reason: 'insufficient_permissions',
          required_permissions: permissions,
          user_permissions: req.user.allPermissions,
          attempted_resource: req.originalUrl
        },
        req,
        'failure',
        'high'
      );
      
      return res.status(403).json({
        status: 'error',
        message: req.t('errors.forbidden'),
        code: 'INSUFFICIENT_PERMISSIONS',
        required: permissions
      });
    }
    next();
  };
};

// Multiple permissions (user must have ALL of them)
exports.requireAllPermissions = (permissions) => {
  return async (req, res, next) => {
    if (!req.user.hasAllPermissions(permissions)) {
      await createAuditLog(
        req.user._id,
        'access_denied',
        'auth',
        { 
          reason: 'insufficient_permissions',
          required_permissions: permissions,
          user_permissions: req.user.allPermissions,
          attempted_resource: req.originalUrl
        },
        req,
        'failure',
        'high'
      );
      
      return res.status(403).json({
        status: 'error',
        message: req.t('errors.forbidden'),
        code: 'INSUFFICIENT_PERMISSIONS',
        required: permissions
      });
    }
    next();
  };
};

// Legacy role-based access (for backward compatibility)
exports.restrictTo = (...roles) => {
  return async (req, res, next) => {
    const userRoleName = req.user.role.name;
    if (!roles.includes(userRoleName)) {
      await createAuditLog(
        req.user._id,
        'access_denied',
        'auth',
        { 
          reason: 'insufficient_role',
          required_roles: roles,
          user_role: userRoleName,
          attempted_resource: req.originalUrl
        },
        req,
        'failure',
        'high'
      );
      
      return res.status(403).json({
        status: 'error',
        message: req.t('errors.forbidden'),
        code: 'INSUFFICIENT_ROLE'
      });
    }
    next();
  };
};

// Super admin check (highest level role)
exports.requireSuperAdmin = async (req, res, next) => {
  if (req.user.role.level < 90) { // Super admin level
    await createAuditLog(
      req.user._id,
      'access_denied',
      'auth',
      { 
        reason: 'requires_super_admin',
        user_level: req.user.role.level,
        attempted_resource: req.originalUrl
      },
      req,
      'failure',
      'critical'
    );
    
    return res.status(403).json({
      status: 'error',
      message: 'Super admin access required',
      code: 'REQUIRES_SUPER_ADMIN'
    });
  }
  next();
};

// Admin only access (backward compatibility)
exports.adminOnly = exports.requirePermission('system:manage');

// Admin or moderator access (backward compatibility)
exports.adminOrModerator = exports.requireAnyPermission(['system:manage', 'user:manage']);

// Export audit log helper for use in controllers
exports.createAuditLog = createAuditLog;