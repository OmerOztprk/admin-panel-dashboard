const User = require('../models/User');
const Role = require('../models/Role');
const APIResponse = require('../utils/response');
const { createAuditLog } = require('../middlewares/auth');

// Get all users (Admin only)
exports.getAllUsers = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const status = req.query.status;
    const roleId = req.query.roleId;
    const search = req.query.search;

    // Build filter object
    const filter = {};
    if (status) filter.status = status;
    if (roleId) filter.role = roleId;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate skip
    const skip = (page - 1) * limit;

    // Get users with pagination
    const users = await User.find(filter)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit);

    // Get total count
    const total = await User.countDocuments(filter);

    // Calculate pagination info
    const totalPages = Math.ceil(total / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    // Log user list access
    await createAuditLog(
      req.user._id,
      'user_list_access',
      'user',
      { 
        total_returned: users.length,
        filters: { status, roleId, search },
        pagination: { page, limit }
      },
      req,
      'success',
      'low'
    );

    APIResponse.success(res, {
      users,
      pagination: {
        currentPage: page,
        totalPages,
        totalUsers: total,
        hasNextPage,
        hasPrevPage,
        limit
      }
    }, 'Users retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Get single user
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    // Log user profile access
    await createAuditLog(
      req.user._id,
      'user_profile_access',
      'user',
      { 
        viewed_user: user._id,
        viewed_user_email: user.email
      },
      req,
      'success',
      'low'
    );

    APIResponse.success(res, { user }, 'User retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Create new user
exports.createUser = async (req, res, next) => {
  try {
    const { name, email, password, role, additionalRoles, status } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return APIResponse.error(res, req.t('user.emailExists'), 400);
    }

    // Validate role exists
    const roleExists = await Role.findById(role);
    if (!roleExists) {
      return APIResponse.error(res, 'Invalid role ID', 400);
    }

    // Validate additional roles if provided
    if (additionalRoles && additionalRoles.length > 0) {
      const validAdditionalRoles = await Role.find({ _id: { $in: additionalRoles } });
      if (validAdditionalRoles.length !== additionalRoles.length) {
        return APIResponse.error(res, 'Some additional roles are invalid', 400);
      }
    }

    const user = await User.create({
      name,
      email,
      password,
      role,
      additionalRoles: additionalRoles || [],
      status: status || 'active'
    });

    // Log user creation
    await createAuditLog(
      req.user._id,
      'user_create',
      'user',
      { 
        created_user: user._id,
        email: user.email,
        role: roleExists.name,
        additional_roles_count: additionalRoles?.length || 0,
        status: user.status,
        created_by: req.user._id
      },
      req,
      'success',
      'medium'
    );

    APIResponse.created(res, { user }, req.t('auth.userCreated'));

  } catch (error) {
    next(error);
  }
};

// Update user
exports.updateUser = async (req, res, next) => {
  try {
    const { name, email, status } = req.body;
    const oldUser = await User.findById(req.params.id);
    
    if (!oldUser) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }
    
    // Check if email is being changed and already exists
    if (email) {
      const existingUser = await User.findOne({ 
        email, 
        _id: { $ne: req.params.id } 
      });
      if (existingUser) {
        return APIResponse.error(res, req.t('user.emailExists'), 400);
      }
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { name, email, status },
      { new: true, runValidators: true }
    );

    // Log changes
    const changes = {};
    if (name !== oldUser.name) changes.name = { from: oldUser.name, to: name };
    if (email !== oldUser.email) changes.email = { from: oldUser.email, to: email };
    if (status !== oldUser.status) changes.status = { from: oldUser.status, to: status };

    await createAuditLog(
      req.user._id,
      'user_update',
      'user',
      { 
        updated_user: user._id,
        changes,
        updated_by: req.user._id
      },
      req,
      'success',
      'medium'
    );

    APIResponse.updated(res, { user }, req.t('auth.userUpdated'));

  } catch (error) {
    next(error);
  }
};

// Assign role to user
exports.assignRole = async (req, res, next) => {
  try {
    const { roleId } = req.body;
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    // Validate role exists
    const role = await Role.findById(roleId);
    if (!role) {
      return APIResponse.error(res, 'Invalid role ID', 400);
    }

    const oldRole = user.role;
    user.role = roleId;
    await user.save();

    // Log role assignment
    await createAuditLog(
      req.user._id,
      'user_role_change',
      'user',
      { 
        user_id: user._id,
        user_email: user.email,
        old_role: oldRole.name,
        new_role: role.name,
        assigned_by: req.user._id
      },
      req,
      'success',
      'high'
    );

    APIResponse.success(res, { user }, 'Role assigned successfully');

  } catch (error) {
    next(error);
  }
};

// Add additional role to user
exports.addAdditionalRole = async (req, res, next) => {
  try {
    const { roleId } = req.body;
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    // Validate role exists
    const role = await Role.findById(roleId);
    if (!role) {
      return APIResponse.error(res, 'Invalid role ID', 400);
    }

    // Check if role is already assigned
    if (user.role.toString() === roleId) {
      return APIResponse.error(res, 'This role is already the primary role', 400);
    }

    if (user.additionalRoles.includes(roleId)) {
      return APIResponse.error(res, 'This role is already assigned as additional role', 400);
    }

    user.additionalRoles.push(roleId);
    await user.save();

    // Log additional role assignment
    await createAuditLog(
      req.user._id,
      'user_additional_role_add',
      'user',
      { 
        user_id: user._id,
        user_email: user.email,
        added_role: role.name,
        assigned_by: req.user._id
      },
      req,
      'success',
      'medium'
    );

    APIResponse.success(res, { user }, 'Additional role added successfully');

  } catch (error) {
    next(error);
  }
};

// Remove additional role from user
exports.removeAdditionalRole = async (req, res, next) => {
  try {
    const { roleId } = req.params;
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    // Check if role exists in additional roles
    if (!user.additionalRoles.includes(roleId)) {
      return APIResponse.error(res, 'Role is not assigned as additional role', 400);
    }

    const role = await Role.findById(roleId);
    user.additionalRoles = user.additionalRoles.filter(id => id.toString() !== roleId);
    await user.save();

    // Log additional role removal
    await createAuditLog(
      req.user._id,
      'user_additional_role_remove',
      'user',
      { 
        user_id: user._id,
        user_email: user.email,
        removed_role: role?.name || 'Unknown',
        removed_by: req.user._id
      },
      req,
      'success',
      'medium'
    );

    APIResponse.success(res, { user }, 'Additional role removed successfully');

  } catch (error) {
    next(error);
  }
};

// Delete user
exports.deleteUser = async (req, res, next) => {
  try {
    // Prevent admin from deleting themselves
    if (req.params.id === req.user.id.toString()) {
      return APIResponse.error(res, 'You cannot delete your own account', 400);
    }

    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return APIResponse.notFound(res, req.t('user.notFound'));
    }

    // Log user deletion
    await createAuditLog(
      req.user._id,
      'user_delete',
      'user',
      { 
        deleted_user: user._id,
        deleted_user_email: user.email,
        deleted_user_role: user.role.name,
        deleted_by: req.user._id
      },
      req,
      'success',
      'high'
    );

    APIResponse.deleted(res, req.t('auth.userDeleted'));

  } catch (error) {
    next(error);
  }
};

// Get user statistics
exports.getUserStats = async (req, res, next) => {
  try {
    const stats = await User.aggregate([
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          activeUsers: {
            $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
          },
          inactiveUsers: {
            $sum: { $cond: [{ $eq: ['$status', 'inactive'] }, 1, 0] }
          },
          suspendedUsers: {
            $sum: { $cond: [{ $eq: ['$status', 'suspended'] }, 1, 0] }
          }
        }
      }
    ]);

    const roleDistribution = await User.aggregate([
      {
        $lookup: {
          from: 'roles',
          localField: 'role',
          foreignField: '_id',
          as: 'roleInfo'
        }
      },
      {
        $unwind: '$roleInfo'
      },
      {
        $group: {
          _id: '$roleInfo.displayName',
          count: { $sum: 1 },
          color: { $first: '$roleInfo.color' }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    // Log stats access
    await createAuditLog(
      req.user._id,
      'user_stats_access',
      'system',
      { 
        total_users: stats[0]?.totalUsers || 0
      },
      req,
      'success',
      'low'
    );

    APIResponse.success(res, {
      userStats: stats[0] || {
        totalUsers: 0,
        activeUsers: 0,
        inactiveUsers: 0,
        suspendedUsers: 0
      },
      roleDistribution
    }, 'User statistics retrieved successfully');

  } catch (error) {
    next(error);
  }
};