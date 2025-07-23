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

    // Get user from token
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

// Restrict to specific roles
exports.restrictTo = (...roles) => {
  return async (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      // Log unauthorized access attempt
      await createAuditLog(
        req.user._id,
        'failed_login',
        'auth',
        { 
          reason: 'insufficient_privileges',
          required_roles: roles,
          user_role: req.user.role,
          attempted_resource: req.originalUrl
        },
        req,
        'failure',
        'high'
      );
      
      return res.status(403).json({
        status: 'error',
        message: req.t('errors.forbidden'),
        code: 'INSUFFICIENT_PRIVILEGES'
      });
    }
    next();
  };
};

// Admin only access
exports.adminOnly = exports.restrictTo('admin');

// Admin or moderator access
exports.adminOrModerator = exports.restrictTo('admin', 'moderator');

// Export audit log helper for use in controllers
exports.createAuditLog = createAuditLog;