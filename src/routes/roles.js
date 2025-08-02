const express = require('express');
const roleController = require('../controllers/roleController');
const { protect, requirePermission, requireSuperAdmin } = require('../middlewares/auth');
const { 
  validateCreateRole,
  validateUpdateRole,
  validateAssignPermissions,
  handleValidationErrors 
} = require('../utils/validation');

const router = express.Router();

// All routes are protected
router.use(protect);

// Role management routes
router.get('/', requirePermission('user:read'), roleController.getAllRoles);
router.get('/stats/overview', requirePermission('system:manage'), roleController.getRoleStats);
router.get('/:id', requirePermission('user:read'), roleController.getRole);
router.post('/', requirePermission('system:manage'), validateCreateRole, handleValidationErrors, roleController.createRole);
router.put('/:id', requirePermission('system:manage'), validateUpdateRole, handleValidationErrors, roleController.updateRole);
router.put('/:id/permissions', requirePermission('system:manage'), validateAssignPermissions, handleValidationErrors, roleController.assignPermissions);
router.delete('/:id', requireSuperAdmin, roleController.deleteRole);

module.exports = router;