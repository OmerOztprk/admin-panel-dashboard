const Role = require('../models/Role');
const Permission = require('../models/Permission');
const User = require('../models/User');
const BaseService = require('./BaseService');

/**
 * Role Management Service
 * Handles all role-related business logic
 */
class RoleService extends BaseService {
  constructor() {
    super(Role);
  }

  // Get all roles with filtering and pagination
  async getAllRoles(query) {
    const { isActive, level, search, includeSystemRoles } = query;

    // Build filter object
    const filter = {};
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (level) filter.level = { $gte: parseInt(level) };
    if (includeSystemRoles === 'false') filter.isSystemRole = false;

    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { displayName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const result = await this.findWithPagination(filter, query);

    // Populate permissions for each role
    const populatedRoles = await Role.populate(result.data, {
      path: 'permissions',
      select: 'name displayName category action resource'
    });

    return {
      ...result,
      data: populatedRoles
    };
  }

  // Get role by ID with populated permissions
  async getRoleById(roleId) {
    const role = await this.findById(roleId, {
      path: 'permissions',
      select: 'name displayName description category action resource isActive'
    });

    if (!role) {
      throw new Error('Role not found');
    }

    // Get users count for this role
    const usersCount = await User.countDocuments({
      $or: [
        { role: roleId },
        { additionalRoles: roleId }
      ]
    });

    return {
      ...role.toJSON(),
      usersCount,
      permissionsCount: role.permissions.length
    };
  }

  // Create new role
  async createRole(roleData) {
    const { name, displayName, description, permissions, level, color, icon, isActive } = roleData;

    // Check if role name already exists
    const existingRole = await Role.findOne({ name });
    if (existingRole) {
      throw new Error('Role with this name already exists');
    }

    // Validate permissions if provided
    let validatedPermissions = [];
    if (permissions && permissions.length > 0) {
      const permissionObjects = await Permission.find({
        _id: { $in: permissions },
        isActive: true
      });

      if (permissionObjects.length !== permissions.length) {
        throw new Error('Some permissions are invalid or inactive');
      }

      validatedPermissions = permissions;
    }

    // Create role
    const role = await Role.create({
      name,
      displayName,
      description,
      permissions: validatedPermissions,
      level: level || 10,
      color: color || '#6B7280',
      icon: icon || 'user',
      isActive: isActive !== false,
      isSystemRole: false // Custom roles are never system roles
    });

    return {
      role: role.toJSON(),
      permissionsAssigned: validatedPermissions.length,
      isCustomRole: true
    };
  }

  // Update existing role
  async updateRole(roleId, updateData, currentUserRole) {
    const { displayName, description, level, color, icon, isActive } = updateData;

    // Get current role
    const oldRole = await Role.findById(roleId);
    if (!oldRole) {
      throw new Error('Role not found');
    }

    // Check if system role can be modified
    if (oldRole.isSystemRole && currentUserRole !== 'super_admin') {
      throw new Error('Only Super Admin can modify system roles');
    }

    // Level validation for system roles
    if (oldRole.isSystemRole && level && level !== oldRole.level) {
      if (currentUserRole !== 'super_admin') {
        throw new Error('Only Super Admin can change system role levels');
      }
    }

    // Update role
    const role = await this.update(roleId, {
      displayName,
      description,
      level,
      color,
      icon,
      isActive
    });

    // Track changes
    const changes = {};
    if (displayName !== oldRole.displayName) {
      changes.displayName = { from: oldRole.displayName, to: displayName };
    }
    if (description !== oldRole.description) {
      changes.description = { from: oldRole.description, to: description };
    }
    if (level !== oldRole.level) {
      changes.level = { from: oldRole.level, to: level };
    }
    if (color !== oldRole.color) {
      changes.color = { from: oldRole.color, to: color };
    }
    if (icon !== oldRole.icon) {
      changes.icon = { from: oldRole.icon, to: icon };
    }
    if (isActive !== oldRole.isActive) {
      changes.isActive = { from: oldRole.isActive, to: isActive };
    }

    return {
      role: role.toJSON(),
      changes,
      isSystemRole: oldRole.isSystemRole
    };
  }

  // Assign permissions to role
  async assignPermissions(roleId, permissionIds, currentUserRole) {
    const role = await Role.findById(roleId);
    if (!role) {
      throw new Error('Role not found');
    }

    // Check permissions for system roles
    if (role.isSystemRole && currentUserRole !== 'super_admin') {
      throw new Error('Only Super Admin can modify system role permissions');
    }

    // Validate all permissions exist and are active
    const validPermissions = await Permission.find({
      _id: { $in: permissionIds },
      isActive: true
    });

    if (validPermissions.length !== permissionIds.length) {
      throw new Error('Some permissions are invalid or inactive');
    }

    // Get old permissions for tracking
    const oldPermissions = role.permissions.map(p => p.toString());

    // Update role permissions
    role.permissions = permissionIds;
    await role.save();

    // Calculate changes
    const addedPermissions = permissionIds.filter(id => !oldPermissions.includes(id.toString()));
    const removedPermissions = oldPermissions.filter(id => !permissionIds.includes(id));

    return {
      role: role.toJSON(),
      permissionChanges: {
        added: addedPermissions.length,
        removed: removedPermissions.length,
        total: permissionIds.length
      },
      addedPermissions,
      removedPermissions
    };
  }

  // Delete role
  async deleteRole(roleId, currentUserRole) {
    const role = await Role.findById(roleId);
    if (!role) {
      throw new Error('Role not found');
    }

    // Check if system role
    if (role.isSystemRole) {
      throw new Error('System roles cannot be deleted');
    }

    // Check if role is in use
    const usersWithRole = await User.countDocuments({
      $or: [
        { role: roleId },
        { additionalRoles: roleId }
      ]
    });

    if (usersWithRole > 0) {
      throw new Error(`Cannot delete role. It is assigned to ${usersWithRole} user(s)`);
    }

    await Role.findByIdAndDelete(roleId);

    return {
      deletedRole: {
        id: role._id,
        name: role.name,
        displayName: role.displayName,
        usersAffected: 0
      }
    };
  }

  // Get role hierarchy
  async getRoleHierarchy() {
    const roles = await Role.find({ isActive: true })
      .select('name displayName level color icon isSystemRole')
      .sort({ level: -1 }); // Highest level first

    return roles.map(role => ({
      ...role.toJSON(),
      isHighestLevel: role.level === 100,
      canManageUsers: role.level >= 50,
      canViewAudit: role.level >= 30
    }));
  }

  // Get role statistics
  async getRoleStatistics() {
    // Basic role statistics
    const stats = await Role.aggregate([
      {
        $group: {
          _id: null,
          totalRoles: { $sum: 1 },
          activeRoles: {
            $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
          },
          systemRoles: {
            $sum: { $cond: [{ $eq: ['$isSystemRole', true] }, 1, 0] }
          },
          customRoles: {
            $sum: { $cond: [{ $eq: ['$isSystemRole', false] }, 1, 0] }
          },
          avgLevel: { $avg: '$level' },
          maxLevel: { $max: '$level' },
          minLevel: { $min: '$level' }
        }
      }
    ]);

    // Role usage statistics
    const roleUsage = await Role.aggregate([
      {
        $lookup: {
          from: 'users',
          let: { roleId: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $or: [
                    { $eq: ['$role', '$$roleId'] },
                    { $in: ['$$roleId', '$additionalRoles'] }
                  ]
                }
              }
            }
          ],
          as: 'users'
        }
      },
      {
        $project: {
          name: 1,
          displayName: 1,
          level: 1,
          color: 1,
          isSystemRole: 1,
          userCount: { $size: '$users' },
          permissionCount: { $size: '$permissions' }
        }
      },
      {
        $sort: { userCount: -1 }
      }
    ]);

    // Permission distribution by category
    const permissionDistribution = await Role.aggregate([
      {
        $lookup: {
          from: 'permissions',
          localField: 'permissions',
          foreignField: '_id',
          as: 'permissionDetails'
        }
      },
      {
        $unwind: '$permissionDetails'
      },
      {
        $group: {
          _id: '$permissionDetails.category',
          roleCount: { $addToSet: '$name' },
          permissionCount: { $sum: 1 }
        }
      },
      {
        $project: {
          category: '$_id',
          roleCount: { $size: '$roleCount' },
          permissionCount: 1
        }
      },
      {
        $sort: { permissionCount: -1 }
      }
    ]);

    return {
      roleStats: stats[0] || {
        totalRoles: 0,
        activeRoles: 0,
        systemRoles: 0,
        customRoles: 0,
        avgLevel: 0,
        maxLevel: 0,
        minLevel: 0
      },
      roleUsage,
      permissionDistribution
    };
  }

  // Get assignable roles for current user
  async getAssignableRoles(currentUserRole, currentUserLevel) {
    let filter = { isActive: true };

    // Super admin can assign any role
    if (currentUserRole !== 'super_admin') {
      // Users can only assign roles with level lower than their own
      filter.level = { $lt: currentUserLevel };
    }

    const roles = await Role.find(filter)
      .select('name displayName level color icon description')
      .sort({ level: -1 });

    return roles.map(role => ({
      ...role.toJSON(),
      canAssign: currentUserRole === 'super_admin' || role.level < currentUserLevel
    }));
  }

  // Validate role assignment
  async validateRoleAssignment(roleId, userLevel) {
    const role = await Role.findById(roleId);
    if (!role) {
      throw new Error('Role not found');
    }

    const canAssign = userLevel >= role.level || userLevel === 100; // Super admin can assign any

    return {
      valid: canAssign,
      role: role.toJSON(),
      requiredLevel: role.level,
      userLevel,
      message: canAssign
        ? 'Role can be assigned'
        : `Insufficient level. Required: ${role.level}, Current: ${userLevel}`
    };
  }

  // Get role permissions by category
  async getRolePermissionsByCategory(roleId) {
    const role = await Role.findById(roleId).populate({
      path: 'permissions',
      select: 'name displayName description category action resource isActive'
    });

    if (!role) {
      throw new Error('Role not found');
    }

    // Group permissions by category
    const permissionsByCategory = role.permissions.reduce((acc, permission) => {
      const category = permission.category;
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(permission);
      return acc;
    }, {});

    return {
      role: {
        id: role._id,
        name: role.name,
        displayName: role.displayName,
        level: role.level
      },
      permissionsByCategory,
      totalPermissions: role.permissions.length,
      categories: Object.keys(permissionsByCategory)
    };
  }
}

module.exports = RoleService;