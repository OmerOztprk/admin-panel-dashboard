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

// User management routes
router.get('/', requirePermission('user:read'), userController.getAllUsers);
router.get('/stats', requirePermission('user:read'), userController.getUserStats);
router.get('/:id', requirePermission('user:read'), userController.getUser);
router.post('/', requirePermission('user:create'), validateCreateUser, handleValidationErrors, userController.createUser);
router.put('/:id', requirePermission('user:update'), validateUpdateUser, handleValidationErrors, userController.updateUser);
router.put('/:id/role', requirePermission('user:update'), validateAssignRole, handleValidationErrors, userController.assignRole);
router.put('/:id/additional-roles', requirePermission('user:update'), userController.addAdditionalRole);
router.delete('/:id/additional-roles/:roleId', requirePermission('user:update'), userController.removeAdditionalRole);
router.delete('/:id', requirePermission('user:delete'), userController.deleteUser);

module.exports = router;