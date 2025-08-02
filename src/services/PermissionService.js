const Permission = require('../models/Permission');
const Role = require('../models/Role');
const BaseService = require('./BaseService');

/**
 * Permission Management Service
 * Handles all permission-related business logic
 */
class PermissionService extends BaseService {
  constructor() {
    super(Permission);
  }

  // Get all permissions with filtering and pagination
  async getAllPermissions(query) {
    const { category, action, resource, isActive, search } = query;

    // Build filter object
    const filter = {};
    if (category) filter.category = category;
    if (action) filter.action = action;
    if (resource) filter.resource = resource;
    if (isActive !== undefined) filter.isActive = isActive === 'true';

    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { displayName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { resource: { $regex: search, $options: 'i' } }
      ];
    }

    const result = await this.findWithPagination(filter, query);

    // Add usage count for each permission
    const permissionsWithUsage = await Promise.all(
      result.data.map(async (permission) => {
        const usageCount = await Role.countDocuments({
          permissions: permission._id,
          isActive: true
        });

        return {
          ...permission.toJSON(),
          usageCount
        };
      })
    );

    return {
      ...result,
      data: permissionsWithUsage
    };
  }

  // Get permission by ID with usage details
  async getPermissionById(permissionId) {
    const permission = await this.findById(permissionId);
    if (!permission) {
      throw new Error('Permission not found');
    }

    // Get roles using this permission
    const rolesUsingPermission = await Role.find({
      permissions: permissionId,
      isActive: true
    }).select('name displayName level color');

    return {
      ...permission.toJSON(),
      usedByRoles: rolesUsingPermission,
      usageCount: rolesUsingPermission.length,
      isSystemCritical: rolesUsingPermission.some(role => role.level >= 80)
    };
  }

  // Create new permission
  async createPermission(permissionData) {
    const { displayName, description, category, resource, action } = permissionData;

    // Check for duplicate resource-action combination
    const existingPermission = await Permission.findOne({ resource, action });
    if (existingPermission) {
      throw new Error(`Permission for ${resource}:${action} already exists`);
    }

    // Generate permission name
    const name = `${resource}:${action}`;

    // Create permission
    const permission = await Permission.create({
      name,
      displayName,
      description,
      category,
      resource,
      action,
      isActive: true
    });

    return {
      permission: permission.toJSON(),
      generatedName: name,
      isCustomPermission: true
    };
  }

  // Update permission
  async updatePermission(permissionId, updateData) {
    const { displayName, description, category, isActive } = updateData;

    // Get current permission
    const oldPermission = await Permission.findById(permissionId);
    if (!oldPermission) {
      throw new Error('Permission not found');
    }

    // Check if permission is in use and being deactivated
    if (isActive === false && oldPermission.isActive === true) {
      const rolesUsingPermission = await Role.countDocuments({
        permissions: permissionId,
        isActive: true
      });

      if (rolesUsingPermission > 0) {
        throw new Error(`Cannot deactivate permission. It is used by ${rolesUsingPermission} active role(s)`);
      }
    }

    // Update permission
    const permission = await this.update(permissionId, {
      displayName,
      description,
      category,
      isActive
    });

    // Track changes
    const changes = {};
    if (displayName !== oldPermission.displayName) {
      changes.displayName = { from: oldPermission.displayName, to: displayName };
    }
    if (description !== oldPermission.description) {
      changes.description = { from: oldPermission.description, to: description };
    }
    if (category !== oldPermission.category) {
      changes.category = { from: oldPermission.category, to: category };
    }
    if (isActive !== oldPermission.isActive) {
      changes.isActive = { from: oldPermission.isActive, to: isActive };
    }

    return {
      permission: permission.toJSON(),
      changes,
      affectsSystemRoles: false // Would need to check this based on roles using it
    };
  }

  // Delete permission
  async deletePermission(permissionId) {
    const permission = await Permission.findById(permissionId);
    if (!permission) {
      throw new Error('Permission not found');
    }

    // Check if permission is in use
    const rolesUsingPermission = await Role.find({
      permissions: permissionId
    }).select('name displayName');

    if (rolesUsingPermission.length > 0) {
      throw new Error(
        `Cannot delete permission. It is used by roles: ${rolesUsingPermission.map(r => r.displayName).join(', ')}`
      );
    }

    await Permission.findByIdAndDelete(permissionId);

    return {
      deletedPermission: {
        id: permission._id,
        name: permission.name,
        displayName: permission.displayName
      },
      rolesAffected: 0
    };
  }

  // Get permission categories with counts
  async getPermissionCategories() {
    const categories = await Permission.aggregate([
      {
        $group: {
          _id: '$category',
          totalPermissions: { $sum: 1 },
          activePermissions: {
            $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
          },
          actions: { $addToSet: '$action' },
          resources: { $addToSet: '$resource' }
        }
      },
      {
        $project: {
          category: '$_id',
          totalPermissions: 1,
          activePermissions: 1,
          uniqueActions: { $size: '$actions' },
          uniqueResources: { $size: '$resources' },
          actions: 1,
          resources: 1
        }
      },
      {
        $sort: { totalPermissions: -1 }
      }
    ]);

    return categories.map(cat => ({
      ...cat,
      usagePercentage: cat.totalPermissions > 0
        ? Math.round((cat.activePermissions / cat.totalPermissions) * 100)
        : 0
    }));
  }

  // Get permissions by category with pagination
  async getPermissionsByCategory(category, options = {}) {
    const filter = { category };
    if (options.isActive !== undefined) {
      filter.isActive = options.isActive;
    }

    const result = await this.findWithPagination(filter, options);

    // Group by action for better organization
    const permissionsByAction = result.data.reduce((acc, permission) => {
      const action = permission.action;
      if (!acc[action]) {
        acc[action] = [];
      }
      acc[action].push(permission);
      return acc;
    }, {});

    return {
      ...result,
      permissionsByAction,
      category,
      actions: Object.keys(permissionsByAction),
      summary: {
        totalInCategory: result.pagination.total,
        uniqueActions: Object.keys(permissionsByAction).length,
        uniqueResources: [...new Set(result.data.map(p => p.resource))].length
      }
    };
  }

  // Get permission statistics
  async getPermissionStatistics() {
    // Basic permission statistics
    const stats = await Permission.aggregate([
      {
        $group: {
          _id: null,
          totalPermissions: { $sum: 1 },
          activePermissions: {
            $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
          },
          uniqueCategories: { $addToSet: '$category' },
          uniqueActions: { $addToSet: '$action' },
          uniqueResources: { $addToSet: '$resource' }
        }
      },
      {
        $project: {
          totalPermissions: 1,
          activePermissions: 1,
          categoriesCount: { $size: '$uniqueCategories' },
          actionsCount: { $size: '$uniqueActions' },
          resourcesCount: { $size: '$uniqueResources' }
        }
      }
    ]);

    // Permission usage by roles
    const usageStats = await Permission.aggregate([
      {
        $lookup: {
          from: 'roles',
          localField: '_id',
          foreignField: 'permissions',
          as: 'roles'
        }
      },
      {
        $project: {
          name: 1,
          category: 1,
          usageCount: { $size: '$roles' }
        }
      },
      {
        $group: {
          _id: '$category',
          avgUsage: { $avg: '$usageCount' },
          maxUsage: { $max: '$usageCount' },
          totalPermissions: { $sum: 1 },
          unusedPermissions: {
            $sum: { $cond: [{ $eq: ['$usageCount', 0] }, 1, 0] }
          }
        }
      }
    ]);

    // Most and least used permissions
    const permissionUsage = await Permission.aggregate([
      {
        $lookup: {
          from: 'roles',
          localField: '_id',
          foreignField: 'permissions',
          as: 'roles'
        }
      },
      {
        $project: {
          name: 1,
          displayName: 1,
          category: 1,
          usageCount: { $size: '$roles' }
        }
      },
      {
        $sort: { usageCount: -1 }
      }
    ]);

    const mostUsed = permissionUsage.slice(0, 5);
    const unused = permissionUsage.filter(p => p.usageCount === 0);

    return {
      permissionStats: stats[0] || {
        totalPermissions: 0,
        activePermissions: 0,
        categoriesCount: 0,
        actionsCount: 0,
        resourcesCount: 0
      },
      categoryUsage: usageStats,
      mostUsedPermissions: mostUsed,
      unusedPermissions: unused,
      usageDistribution: {
        used: permissionUsage.filter(p => p.usageCount > 0).length,
        unused: unused.length
      }
    };
  }

  // Bulk update permissions
  async bulkUpdatePermissions(updates) {
    const results = {
      successful: [],
      failed: [],
      totalProcessed: updates.length
    };

    for (const update of updates) {
      try {
        const { id, ...updateData } = update;
        const updatedPermission = await this.updatePermission(id, updateData);
        results.successful.push({
          id,
          permission: updatedPermission.permission,
          changes: updatedPermission.changes
        });
      } catch (error) {
        results.failed.push({
          id: update.id,
          error: error.message
        });
      }
    }

    return results;
  }

  // Get available actions for a resource
  async getAvailableActions(resource) {
    const permissions = await Permission.find({ resource })
      .select('action displayName description isActive')
      .sort('action');

    const allActions = ['create', 'read', 'update', 'delete', 'manage', 'view'];
    const usedActions = permissions.map(p => p.action);
    const availableActions = allActions.filter(action => !usedActions.includes(action));

    return {
      resource,
      existingPermissions: permissions,
      availableActions,
      canCreateNew: availableActions.length > 0
    };
  }

  // Validate permission data
  validatePermissionData(permissionData) {
    const { resource, action, category } = permissionData;

    const validCategories = ['user', 'role', 'system', 'content', 'audit', 'settings'];
    const validActions = ['create', 'read', 'update', 'delete', 'manage', 'view'];

    const errors = [];

    if (!validCategories.includes(category)) {
      errors.push(`Invalid category. Must be one of: ${validCategories.join(', ')}`);
    }

    if (!validActions.includes(action)) {
      errors.push(`Invalid action. Must be one of: ${validActions.join(', ')}`);
    }

    if (!resource || resource.length < 2) {
      errors.push('Resource must be at least 2 characters long');
    }

    return {
      valid: errors.length === 0,
      errors,
      generatedName: errors.length === 0 ? `${resource}:${action}` : null
    };
  }
}

module.exports = PermissionService;