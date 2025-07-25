const express = require('express');
const permissionController = require('../controllers/permissionController');
const { protect, requirePermission } = require('../middlewares/auth');
const { 
  validateCreatePermission,
  validateUpdatePermission,
  handleValidationErrors 
} = require('../utils/validation');

const router = express.Router();

// All routes are protected and require system management permission
router.use(protect);
router.use(requirePermission('system:manage'));

// Permission CRUD routes
router.get('/', permissionController.getAllPermissions);
router.get('/categories', permissionController.getPermissionCategories);
router.get('/:id', permissionController.getPermission);

router.post('/', 
  validateCreatePermission,
  handleValidationErrors,
  permissionController.createPermission
);

router.put('/:id',
  validateUpdatePermission,
  handleValidationErrors,
  permissionController.updatePermission
);

router.delete('/:id', permissionController.deletePermission);

module.exports = router;