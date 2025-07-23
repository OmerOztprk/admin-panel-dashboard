const jwt = require('jsonwebtoken');
const User = require('../models/User');
const config = require('../config');

// Protect routes - JWT verification
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

    // Verify token
    const decoded = jwt.verify(token, config.jwt.secret);

    // Get user from token
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: req.t('errors.unauthorized')
      });
    }

    // Check if user is active
    if (user.status !== 'active') {
      return res.status(401).json({
        status: 'error',
        message: req.t('errors.unauthorized')
      });
    }

    // Check if user is locked
    if (user.isLocked) {
      return res.status(401).json({
        status: 'error',
        message: 'Account temporarily locked due to too many failed login attempts'
      });
    }

    // Grant access to protected route
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({
      status: 'error',
      message: req.t('errors.unauthorized')
    });
  }
};

// Restrict to specific roles
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        message: req.t('errors.forbidden')
      });
    }
    next();
  };
};

// Admin only access
exports.adminOnly = exports.restrictTo('admin');

// Admin or moderator access
exports.adminOrModerator = exports.restrictTo('admin', 'moderator');