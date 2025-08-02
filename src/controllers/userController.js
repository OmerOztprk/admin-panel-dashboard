const APIResponse = require('../utils/response');
const { handleValidationErrors } = require('../utils/validation');
const { userService, auditService } = require('../services');

/**
 * User Management Controller
 * Handles HTTP requests and delegates business logic to UserService
 */
class UserController {

  // Get all users with filtering and pagination
  async getAllUsers(req, res, next) {
    try {
      const result = await userService.getAllUsers(req.query);

      // Create audit log - userId kontrolü ekleyelim
      if (req.user && req.user.id) {
        await auditService.createLog(
          req.user.id,
          'list',
          'user',
          {
            filters: req.query,
            resultCount: result.data.length,
            totalUsers: result.pagination.total
          },
          req,
          'success',
          'low'
        );
      }

      APIResponse.success(res, result, 'Users retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get user by ID
  async getUser(req, res, next) {
    try {
      const user = await userService.getUserById(req.params.id);

      if (!user) {
        return APIResponse.notFound(res, req.t('user.notFound'));
      }

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'view',
        'user',
        {
          targetUserId: req.params.id,
          targetUserEmail: user.email
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, { user }, 'User retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Create new user
  async createUser(req, res, next) {
    try {
      handleValidationErrors(req, res, () => { });

      const result = await userService.createUser(req.body);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'create',
        'user',
        {
          createdUserId: result.user.id,
          createdUserEmail: result.user.email,
          assignedRole: result.roleInfo.name,
          additionalRoles: result.additionalRolesCount
        },
        req,
        'success',
        'medium'
      );

      APIResponse.created(res, { user: result.user }, req.t('user.created'));
    } catch (error) {
      // Create audit log for failed user creation
      await auditService.createLog(
        req.user.id,
        'create',
        'user',
        {
          attemptedEmail: req.body.email,
          error: error.message
        },
        req,
        'failure',
        'medium'
      );

      next(error);
    }
  }

  // Update user
  async updateUser(req, res, next) {
    try {
      handleValidationErrors(req, res, () => { });

      const result = await userService.updateUser(req.params.id, req.body);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'update',
        'user',
        {
          targetUserId: req.params.id,
          changes: result.changes,
          updatedBy: req.user.email
        },
        req,
        'success',
        'medium'
      );

      APIResponse.updated(res, { user: result.user }, req.t('user.updated'));
    } catch (error) {
      // Create audit log for failed user update
      await auditService.createLog(
        req.user.id,
        'update',
        'user',
        {
          targetUserId: req.params.id,
          error: error.message
        },
        req,
        'failure',
        'medium'
      );

      next(error);
    }
  }

  // Delete user
  async deleteUser(req, res, next) {
    try {
      const result = await userService.deleteUser(req.params.id, req.user.id);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'delete',
        'user',
        {
          deletedUser: result.deletedUser,
          deletedBy: req.user.email
        },
        req,
        'success',
        'high'
      );

      APIResponse.deleted(res, null, req.t('user.deleted'));
    } catch (error) {
      // Create audit log for failed user deletion
      await auditService.createLog(
        req.user.id,
        'delete',
        'user',
        {
          targetUserId: req.params.id,
          error: error.message
        },
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Assign role to user
  async assignRole(req, res, next) {
    try {
      handleValidationErrors(req, res, () => { });

      const { roleId } = req.body;
      const result = await userService.assignRole(req.params.id, roleId);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'role_change',
        'user',
        {
          targetUserId: req.params.id,
          oldRole: result.oldRole,
          newRole: result.newRole,
          changedBy: req.user.email
        },
        req,
        'success',
        'high'
      );

      APIResponse.updated(res, { user: result.user }, 'Role assigned successfully');
    } catch (error) {
      next(error);
    }
  }

  // Add additional role to user
  async addAdditionalRole(req, res, next) {
    try {
      handleValidationErrors(req, res, () => { });

      const { roleId } = req.body;
      const result = await userService.addAdditionalRole(req.params.id, roleId);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'additional_role_add',
        'user',
        {
          targetUserId: req.params.id,
          addedRole: result.addedRole,
          addedBy: req.user.email
        },
        req,
        'success',
        'medium'
      );

      APIResponse.updated(res, { user: result.user }, 'Additional role added successfully');
    } catch (error) {
      next(error);
    }
  }

  // Remove additional role from user
  async removeAdditionalRole(req, res, next) {
    try {
      const result = await userService.removeAdditionalRole(req.params.id, req.params.roleId);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'additional_role_remove',
        'user',
        {
          targetUserId: req.params.id,
          removedRole: result.removedRole,
          removedBy: req.user.email
        },
        req,
        'success',
        'medium'
      );

      APIResponse.updated(res, { user: result.user }, 'Additional role removed successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get user statistics
  async getUserStats(req, res, next) {
    try {
      const stats = await userService.getUserStatistics();

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'statistics',
        'user',
        {
          requestedBy: req.user.email,
          statsType: 'user_overview'
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, stats, 'User statistics retrieved successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export instance methods
const userController = new UserController();

module.exports = {
  getAllUsers: userController.getAllUsers.bind(userController),
  getUser: userController.getUser.bind(userController),
  createUser: userController.createUser.bind(userController),
  updateUser: userController.updateUser.bind(userController),
  deleteUser: userController.deleteUser.bind(userController),
  assignRole: userController.assignRole.bind(userController),
  addAdditionalRole: userController.addAdditionalRole.bind(userController),
  removeAdditionalRole: userController.removeAdditionalRole.bind(userController),
  getUserStats: userController.getUserStats.bind(userController)
};