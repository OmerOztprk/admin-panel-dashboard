const User = require('../models/User');
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
    const role = req.query.role;
    const search = req.query.search;

    // Build filter object
    const filter = {};
    if (status) filter.status = status;
    if (role) filter.role = role;
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
        filters: { status, role, search },
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

// Get single user (Admin/Moderator)
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

// Create new user (Admin only)
exports.createUser = async (req, res, next) => {
  try {
    const { name, email, password, role, status } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return APIResponse.error(res, req.t('user.emailExists'), 400);
    }

    const user = await User.create({
      name,
      email,
      password,
      role: role || 'user',
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
        role: user.role,
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

// Update user (Admin/Moderator)
exports.updateUser = async (req, res, next) => {
  try {
    const { name, email, role, status } = req.body;
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

    // Prevent non-admin users from updating to admin role
    if (role === 'admin' && req.user.role !== 'admin') {
      return APIResponse.forbidden(res, 'Only admins can assign admin role');
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { name, email, role, status },
      { new: true, runValidators: true }
    );

    // Log changes
    const changes = {};
    if (name !== oldUser.name) changes.name = { from: oldUser.name, to: name };
    if (email !== oldUser.email) changes.email = { from: oldUser.email, to: email };
    if (role !== oldUser.role) changes.role = { from: oldUser.role, to: role };
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
      role !== oldUser.role ? 'high' : 'medium'
    );

    APIResponse.updated(res, { user }, req.t('auth.userUpdated'));

  } catch (error) {
    next(error);
  }
};

// Delete user (Admin only)
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
        deleted_user_role: user.role,
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

// Get user statistics (Admin only)
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

    const roleStats = await User.aggregate([
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 }
        }
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
      roleDistribution: roleStats
    }, 'User statistics retrieved successfully');

  } catch (error) {
    next(error);
  }
};