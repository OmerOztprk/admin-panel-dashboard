const APIResponse = require('../utils/response');
const { handleValidationErrors } = require('../utils/validation');
const { roleService, auditService } = require('../services');

/**
 * Role Management Controller
 * Handles HTTP requests and delegates business logic to RoleService
 */
class RoleController {

  // Get all roles with filtering and pagination
  async getAllRoles(req, res, next) {
    try {
      const result = await roleService.getAllRoles(req.query);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'list',
        'role',
        { 
          filters: req.query,
          resultCount: result.data.length,
          totalRoles: result.pagination.total
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, result, 'Roles retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get role by ID
  async getRole(req, res, next) {
    try {
      const role = await roleService.getRoleById(req.params.id);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'view',
        'role',
        { 
          roleId: req.params.id,
          roleName: role.name,
          usersCount: role.usersCount
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, { role }, 'Role retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Create new role
  async createRole(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await roleService.createRole(req.body);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'create',
        'role',
        { 
          createdRoleId: result.role.id,
          roleName: result.role.name,
          permissionsAssigned: result.permissionsAssigned,
          isCustomRole: result.isCustomRole
        },
        req,
        'success',
        'high'
      );

      APIResponse.created(res, { role: result.role }, 'Role created successfully');
    } catch (error) {
      // Create audit log for failed role creation
      await auditService.createLog(
        req.user.id,
        'create',
        'role',
        { 
          attemptedRoleName: req.body.name,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Update role
  async updateRole(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await roleService.updateRole(
        req.params.id, 
        req.body, 
        req.user.role.name
      );

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'update',
        'role',
        { 
          roleId: req.params.id,
          changes: result.changes,
          isSystemRole: result.isSystemRole,
          updatedBy: req.user.email
        },
        req,
        'success',
        result.isSystemRole ? 'critical' : 'high'
      );

      APIResponse.updated(res, { role: result.role }, 'Role updated successfully');
    } catch (error) {
      // Create audit log for failed role update
      await auditService.createLog(
        req.user.id,
        'update',
        'role',
        { 
          roleId: req.params.id,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Delete role
  async deleteRole(req, res, next) {
    try {
      const result = await roleService.deleteRole(req.params.id, req.user.role.name);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'delete',
        'role',
        { 
          deletedRole: result.deletedRole,
          deletedBy: req.user.email
        },
        req,
        'success',
        'critical'
      );

      APIResponse.deleted(res, null, 'Role deleted successfully');
    } catch (error) {
      // Create audit log for failed role deletion
      await auditService.createLog(
        req.user.id,
        'delete',
        'role',
        { 
          roleId: req.params.id,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Assign permissions to role
  async assignPermissions(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const { permissions } = req.body;
      const result = await roleService.assignPermissions(
        req.params.id, 
        permissions, 
        req.user.role.name
      );

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'permission_assign',
        'role',
        { 
          roleId: req.params.id,
          permissionChanges: result.permissionChanges,
          addedPermissions: result.addedPermissions,
          removedPermissions: result.removedPermissions,
          assignedBy: req.user.email
        },
        req,
        'success',
        'critical'
      );

      APIResponse.updated(res, { 
        role: result.role, 
        changes: result.permissionChanges 
      }, 'Permissions assigned successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get role statistics
  async getRoleStats(req, res, next) {
    try {
      const stats = await roleService.getRoleStatistics();

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'statistics',
        'role',
        { 
          requestedBy: req.user.email,
          statsType: 'role_overview'
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, stats, 'Role statistics retrieved successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export instance methods
const roleController = new RoleController();

module.exports = {
  getAllRoles: roleController.getAllRoles.bind(roleController),
  getRole: roleController.getRole.bind(roleController),
  createRole: roleController.createRole.bind(roleController),
  updateRole: roleController.updateRole.bind(roleController),
  deleteRole: roleController.deleteRole.bind(roleController),
  assignPermissions: roleController.assignPermissions.bind(roleController),
  getRoleStats: roleController.getRoleStats.bind(roleController)
};