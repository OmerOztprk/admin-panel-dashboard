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

// Get all roles (requires user:read permission)
router.get('/', 
  requirePermission('user:read'), 
  roleController.getAllRoles
);

// Get role statistics (requires system:manage permission)
router.get('/stats/overview', 
  requirePermission('system:manage'), 
  roleController.getRoleStats
);

// Get role by ID (requires user:read permission)
router.get('/:id', 
  requirePermission('user:read'), 
  roleController.getRole
);

// Create new role (requires system:manage permission)
router.post('/',
  requirePermission('system:manage'),
  validateCreateRole,
  handleValidationErrors,
  roleController.createRole
);

// Update role (requires system:manage permission)
router.put('/:id',
  requirePermission('system:manage'),
  validateUpdateRole,
  handleValidationErrors,
  roleController.updateRole
);

// Assign permissions to role (requires system:manage permission)
router.put('/:id/permissions',
  requirePermission('system:manage'),
  validateAssignPermissions,
  handleValidationErrors,
  roleController.assignPermissions
);

// Delete role (requires super admin)
router.delete('/:id', 
  requireSuperAdmin,
  roleController.deleteRole
);

module.exports = router;