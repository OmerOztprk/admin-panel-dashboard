const Role = require('../models/Role');
const Permission = require('../models/Permission');
const User = require('../models/User');
const APIResponse = require('../utils/response');
const { createAuditLog } = require('../middlewares/auth');

// Get all roles
exports.getAllRoles = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const isActive = req.query.isActive;
    const search = req.query.search;

    // Build filter
    const filter = {};
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { displayName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const roles = await Role.find(filter)
      .sort({ level: -1, name: 1 })
      .skip(skip)
      .limit(limit);

    const total = await Role.countDocuments(filter);

    // Get user counts for each role
    const rolesWithUserCount = await Promise.all(
      roles.map(async (role) => {
        const userCount = await User.countDocuments({ role: role._id });
        return {
          ...role.toObject(),
          userCount
        };
      })
    );

    // Log access
    await createAuditLog(
      req.user._id,
      'role_list_access',
      'system',
      { total_returned: roles.length },
      req,
      'success',
      'low'
    );

    APIResponse.success(res, {
      roles: rolesWithUserCount,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalRoles: total,
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
        limit
      }
    }, 'Roles retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Get role by ID
exports.getRole = async (req, res, next) => {
  try {
    const role = await Role.findById(req.params.id);
    
    if (!role) {
      return APIResponse.notFound(res, 'Role not found');
    }

    // Get user count
    const userCount = await User.countDocuments({ role: role._id });

    APIResponse.success(res, { 
      role: {
        ...role.toObject(),
        userCount
      }
    }, 'Role retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Create new role
exports.createRole = async (req, res, next) => {
  try {
    const { name, displayName, description, permissions, level, color, icon } = req.body;

    // Validate permissions exist
    if (permissions && permissions.length > 0) {
      const validPermissions = await Permission.find({ _id: { $in: permissions } });
      if (validPermissions.length !== permissions.length) {
        return APIResponse.error(res, 'Some permissions are invalid', 400);
      }
    }

    const role = await Role.create({
      name,
      displayName,
      description,
      permissions: permissions || [],
      level: level || 1,
      color: color || '#6B7280',
      icon: icon || 'user'
    });

    // Log creation
    await createAuditLog(
      req.user._id,
      'role_create',
      'system',
      { 
        created_role: role._id,
        name: role.name,
        permission_count: permissions?.length || 0,
        level: role.level
      },
      req,
      'success',
      'high'
    );

    APIResponse.created(res, { role }, 'Role created successfully');

  } catch (error) {
    next(error);
  }
};

// Update role
exports.updateRole = async (req, res, next) => {
  try {
    const { displayName, description, permissions, level, color, icon, isActive } = req.body;
    const oldRole = await Role.findById(req.params.id);
    
    if (!oldRole) {
      return APIResponse.notFound(res, 'Role not found');
    }

    // Prevent updating system roles
    if (oldRole.isSystemRole) {
      return APIResponse.error(res, 'System roles cannot be modified', 400);
    }

    // Validate permissions exist
    if (permissions && permissions.length > 0) {
      const validPermissions = await Permission.find({ _id: { $in: permissions } });
      if (validPermissions.length !== permissions.length) {
        return APIResponse.error(res, 'Some permissions are invalid', 400);
      }
    }

    const role = await Role.findByIdAndUpdate(
      req.params.id,
      { displayName, description, permissions, level, color, icon, isActive },
      { new: true, runValidators: true }
    );

    // Log changes
    const changes = {};
    if (displayName !== oldRole.displayName) changes.displayName = { from: oldRole.displayName, to: displayName };
    if (description !== oldRole.description) changes.description = { from: oldRole.description, to: description };
    if (level !== oldRole.level) changes.level = { from: oldRole.level, to: level };
    if (permissions && JSON.stringify(permissions) !== JSON.stringify(oldRole.permissions.map(p => p._id))) {
      changes.permissions = { from: oldRole.permissions.length, to: permissions.length };
    }

    await createAuditLog(
      req.user._id,
      'role_update',
      'system',
      { 
        updated_role: role._id,
        changes
      },
      req,
      'success',
      'high'
    );

    APIResponse.updated(res, { role }, 'Role updated successfully');

  } catch (error) {
    next(error);
  }
};

// Delete role
exports.deleteRole = async (req, res, next) => {
  try {
    const role = await Role.findById(req.params.id);
    
    if (!role) {
      return APIResponse.notFound(res, 'Role not found');
    }

    // Prevent deleting system roles
    if (role.isSystemRole) {
      return APIResponse.error(res, 'System roles cannot be deleted', 400);
    }

    // Check if role is in use
    const userCount = await User.countDocuments({ role: role._id });
    if (userCount > 0) {
      return APIResponse.error(res, `Cannot delete role. ${userCount} users are assigned to this role`, 400);
    }

    await Role.findByIdAndDelete(req.params.id);

    // Log deletion
    await createAuditLog(
      req.user._id,
      'role_delete',
      'system',
      { 
        deleted_role: role._id,
        name: role.name,
        permission_count: role.permissions.length
      },
      req,
      'success',
      'high'
    );

    APIResponse.deleted(res, 'Role deleted successfully');

  } catch (error) {
    next(error);
  }
};

// Assign permissions to role
exports.assignPermissions = async (req, res, next) => {
  try {
    const { permissions } = req.body;
    const role = await Role.findById(req.params.id);
    
    if (!role) {
      return APIResponse.notFound(res, 'Role not found');
    }

    // Validate permissions exist
    const validPermissions = await Permission.find({ _id: { $in: permissions } });
    if (validPermissions.length !== permissions.length) {
      return APIResponse.error(res, 'Some permissions are invalid', 400);
    }

    const oldPermissionCount = role.permissions.length;
    role.permissions = permissions;
    await role.save();

    // Log permission assignment
    await createAuditLog(
      req.user._id,
      'role_permissions_update',
      'system',
      { 
        role_id: role._id,
        role_name: role.name,
        old_permission_count: oldPermissionCount,
        new_permission_count: permissions.length
      },
      req,
      'success',
      'high'
    );

    APIResponse.success(res, { role }, 'Permissions assigned successfully');

  } catch (error) {
    next(error);
  }
};

// Get role statistics
exports.getRoleStats = async (req, res, next) => {
  try {
    const stats = await Role.aggregate([
      {
        $group: {
          _id: null,
          totalRoles: { $sum: 1 },
          activeRoles: { $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] } },
          systemRoles: { $sum: { $cond: [{ $eq: ['$isSystemRole', true] }, 1, 0] } },
          averageLevel: { $avg: '$level' }
        }
      }
    ]);

    // Get permission distribution
    const permissionStats = await Role.aggregate([
      { $unwind: '$permissions' },
      { $group: { _id: '$permissions', roles: { $addToSet: '$name' } } },
      { $lookup: { from: 'permissions', localField: '_id', foreignField: '_id', as: 'permission' } },
      { $unwind: '$permission' },
      { $project: { permission: '$permission.name', roleCount: { $size: '$roles' } } },
      { $sort: { roleCount: -1 } },
      { $limit: 10 }
    ]);

    APIResponse.success(res, {
      roleStats: stats[0] || { totalRoles: 0, activeRoles: 0, systemRoles: 0, averageLevel: 0 },
      topPermissions: permissionStats
    }, 'Role statistics retrieved successfully');

  } catch (error) {
    next(error);
  }
};