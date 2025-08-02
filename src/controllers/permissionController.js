const APIResponse = require('../utils/response');
const { handleValidationErrors } = require('../utils/validation');
const { permissionService, auditService } = require('../services');

/**
 * Permission Management Controller
 * Handles HTTP requests and delegates business logic to PermissionService
 */
class PermissionController {

  // Get all permissions with filtering and pagination
  async getAllPermissions(req, res, next) {
    try {
      const result = await permissionService.getAllPermissions(req.query);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'list',
        'permission',
        { 
          filters: req.query,
          resultCount: result.data.length,
          totalPermissions: result.pagination.total
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, result, 'Permissions retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get permission by ID
  async getPermission(req, res, next) {
    try {
      const permission = await permissionService.getPermissionById(req.params.id);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'view',
        'permission',
        { 
          permissionId: req.params.id,
          permissionName: permission.name,
          usageCount: permission.usageCount
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, { permission }, 'Permission retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Create new permission
  async createPermission(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await permissionService.createPermission(req.body);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'create',
        'permission',
        { 
          createdPermissionId: result.permission.id,
          permissionName: result.permission.name,
          generatedName: result.generatedName,
          isCustomPermission: result.isCustomPermission
        },
        req,
        'success',
        'high'
      );

      APIResponse.created(res, { permission: result.permission }, 'Permission created successfully');
    } catch (error) {
      // Create audit log for failed permission creation
      await auditService.createLog(
        req.user.id,
        'create',
        'permission',
        { 
          attemptedResource: req.body.resource,
          attemptedAction: req.body.action,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Update permission
  async updatePermission(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await permissionService.updatePermission(req.params.id, req.body);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'update',
        'permission',
        { 
          permissionId: req.params.id,
          changes: result.changes,
          affectsSystemRoles: result.affectsSystemRoles,
          updatedBy: req.user.email
        },
        req,
        'success',
        result.affectsSystemRoles ? 'critical' : 'high'
      );

      APIResponse.updated(res, { permission: result.permission }, 'Permission updated successfully');
    } catch (error) {
      // Create audit log for failed permission update
      await auditService.createLog(
        req.user.id,
        'update',
        'permission',
        { 
          permissionId: req.params.id,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Delete permission
  async deletePermission(req, res, next) {
    try {
      const result = await permissionService.deletePermission(req.params.id);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'delete',
        'permission',
        { 
          deletedPermission: result.deletedPermission,
          rolesAffected: result.rolesAffected,
          deletedBy: req.user.email
        },
        req,
        'success',
        'critical'
      );

      APIResponse.deleted(res, null, 'Permission deleted successfully');
    } catch (error) {
      // Create audit log for failed permission deletion
      await auditService.createLog(
        req.user.id,
        'delete',
        'permission',
        { 
          permissionId: req.params.id,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Get permission categories
  async getPermissionCategories(req, res, next) {
    try {
      const categories = await permissionService.getPermissionCategories();

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'categories',
        'permission',
        { 
          requestedBy: req.user.email,
          categoriesCount: categories.length
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, { categories }, 'Permission categories retrieved successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export instance methods
const permissionController = new PermissionController();

module.exports = {
  getAllPermissions: permissionController.getAllPermissions.bind(permissionController),
  getPermission: permissionController.getPermission.bind(permissionController),
  createPermission: permissionController.createPermission.bind(permissionController),
  updatePermission: permissionController.updatePermission.bind(permissionController),
  deletePermission: permissionController.deletePermission.bind(permissionController),
  getPermissionCategories: permissionController.getPermissionCategories.bind(permissionController)
};