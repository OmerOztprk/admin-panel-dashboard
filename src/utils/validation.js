const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');

// Handle validation errors
exports.handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      message: req.t('errors.validation'),
      errors: errors.array()
    });
  }
  next();
};

// User validation rules
exports.validateRegister = [
  body('name')
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  body('role')
    .optional()
    .custom((value) => {
      // Allow both ObjectId and role name
      if (mongoose.Types.ObjectId.isValid(value)) {
        return true; // Valid ObjectId
      }
      // Allow role names (string with specific pattern)
      if (typeof value === 'string' && /^[a-z0-9_]+$/.test(value)) {
        return true;
      }
      throw new Error('Role must be a valid ObjectId or role name (lowercase letters, numbers, underscores only)');
    })
];

exports.validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

exports.validateUpdateUser = [
  body('name')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail()
];

exports.validateChangePassword = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must contain at least one lowercase letter, one uppercase letter, and one number')
];

exports.validateCreateUser = [
  body('name')
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  body('role')
    .notEmpty()
    .withMessage('Role is required')
    .isMongoId()
    .withMessage('Invalid role ID'),
  body('status')
    .optional()
    .isIn(['active', 'inactive', 'suspended'])
    .withMessage('Status must be active, inactive, or suspended')
];

// Permission validation rules
exports.validateCreatePermission = [
  body('displayName')
    .notEmpty()
    .withMessage('Display name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Display name must be between 2 and 100 characters'),
  body('description')
    .notEmpty()
    .withMessage('Description is required')
    .isLength({ min: 10, max: 500 })
    .withMessage('Description must be between 10 and 500 characters'),
  body('category')
    .notEmpty()
    .withMessage('Category is required')
    .isIn(['user', 'role', 'system', 'content', 'audit', 'settings'])
    .withMessage('Invalid category'),
  body('resource')
    .notEmpty()
    .withMessage('Resource is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Resource must be between 2 and 50 characters'),
  body('action')
    .notEmpty()
    .withMessage('Action is required')
    .isIn(['create', 'read', 'update', 'delete', 'manage', 'view'])
    .withMessage('Invalid action')
];

exports.validateUpdatePermission = [
  body('displayName')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Display name must be between 2 and 100 characters'),
  body('description')
    .optional()
    .isLength({ min: 10, max: 500 })
    .withMessage('Description must be between 10 and 500 characters'),
  body('category')
    .optional()
    .isIn(['user', 'role', 'system', 'content', 'audit', 'settings'])
    .withMessage('Invalid category'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean')
];

// Role validation rules
exports.validateCreateRole = [
  body('name')
    .notEmpty()
    .withMessage('Role name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Role name must be between 2 and 50 characters')
    .matches(/^[a-z0-9_]+$/)
    .withMessage('Role name must contain only lowercase letters, numbers, and underscores'),
  body('displayName')
    .notEmpty()
    .withMessage('Display name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Display name must be between 2 and 100 characters'),
  body('description')
    .notEmpty()
    .withMessage('Description is required')
    .isLength({ min: 10, max: 500 })
    .withMessage('Description must be between 10 and 500 characters'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .optional()
    .isMongoId()
    .withMessage('Invalid permission ID'),
  body('level')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Level must be between 1 and 100'),
  body('color')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Color must be a valid hex color'),
  body('icon')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Icon name must be between 1 and 50 characters')
];

exports.validateUpdateRole = [
  body('displayName')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Display name must be between 2 and 100 characters'),
  body('description')
    .optional()
    .isLength({ min: 10, max: 500 })
    .withMessage('Description must be between 10 and 500 characters'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .optional()
    .isMongoId()
    .withMessage('Invalid permission ID'),
  body('level')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Level must be between 1 and 100'),
  body('color')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Color must be a valid hex color'),
  body('icon')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Icon name must be between 1 and 50 characters'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean')
];

exports.validateAssignPermissions = [
  body('permissions')
    .isArray({ min: 0 })
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .isMongoId()
    .withMessage('Invalid permission ID')
];

exports.validateAssignRole = [
  body('roleId')
    .notEmpty()
    .withMessage('Role ID is required')
    .isMongoId()
    .withMessage('Invalid role ID')
];