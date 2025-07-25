const express = require('express');
const userController = require('../controllers/userController');
const { 
  protect, 
  requirePermission, 
  requireAnyPermission,
  requireSuperAdmin 
} = require('../middlewares/auth');
const { 
  validateCreateUser, 
  validateUpdateUser,
  validateAssignRole,
  handleValidationErrors 
} = require('../utils/validation');

const router = express.Router();

// All routes are protected
router.use(protect);

// Get all users (requires user:read permission)
router.get('/', 
  requirePermission('user:read'), 
  userController.getAllUsers
);

// Get user statistics (requires user:read permission)
router.get('/stats', 
  requirePermission('user:read'), 
  userController.getUserStats
);

// Get user by ID (requires user:read permission)
router.get('/:id', 
  requirePermission('user:read'), 
  userController.getUser
);

// Create new user (requires user:create permission)
router.post('/',
  requirePermission('user:create'),
  validateCreateUser,
  handleValidationErrors,
  userController.createUser
);

// Update user (requires user:update permission)
router.put('/:id',
  requirePermission('user:update'),
  validateUpdateUser,
  handleValidationErrors,
  userController.updateUser
);

// Assign role to user (requires user:update permission)
router.put('/:id/role',
  requirePermission('user:update'),
  validateAssignRole,
  handleValidationErrors,
  userController.assignRole
);

// Add additional role to user (requires user:update permission)
router.put('/:id/additional-roles',
  requirePermission('user:update'),
  userController.addAdditionalRole
);

// Remove additional role from user (requires user:update permission)
router.delete('/:id/additional-roles/:roleId',
  requirePermission('user:update'),
  userController.removeAdditionalRole
);

// Delete user (requires user:delete permission)
router.delete('/:id', 
  requirePermission('user:delete'),
  userController.deleteUser
);

module.exports = router;