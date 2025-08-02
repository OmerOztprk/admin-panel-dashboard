const User = require('../models/User');
const Role = require('../models/Role');
const BaseService = require('./BaseService');

/**
 * User Management Service
 * Handles all user-related business logic
 */
class UserService extends BaseService {
  constructor() {
    super(User);
  }

  // Get all users with filtering and pagination
  async getAllUsers(query) {
    const { status, roleId, search } = query;

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

    const result = await this.findWithPagination(filter, query);

    // Populate role information
    const populatedUsers = await User.populate(result.data, {
      path: 'role',
      select: 'name displayName color level'
    });

    return {
      ...result,
      data: populatedUsers
    };
  }

  // Get user by ID with role information
  async getUserById(userId) {
    return await this.findById(userId, [
      { path: 'role', select: 'name displayName permissions level color icon' },
      { path: 'additionalRoles', select: 'name displayName permissions level color icon' }
    ]);
  }

  // Create a new user
  async createUser(userData) {
    const { name, email, password, role, additionalRoles, status } = userData;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // Validate primary role
    const roleExists = await Role.findById(role);
    if (!roleExists) {
      throw new Error('Invalid role ID');
    }

    // Validate additional roles if provided
    if (additionalRoles && additionalRoles.length > 0) {
      const validAdditionalRoles = await Role.find({ _id: { $in: additionalRoles } });
      if (validAdditionalRoles.length !== additionalRoles.length) {
        throw new Error('Some additional roles are invalid');
      }
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      role,
      additionalRoles: additionalRoles || [],
      status: status || 'active'
    });

    return {
      user: user.toJSON(),
      roleInfo: roleExists,
      additionalRolesCount: additionalRoles?.length || 0
    };
  }

  // Update user information
  async updateUser(userId, updateData) {
    const { name, email, status } = updateData;

    // Get current user
    const oldUser = await User.findById(userId);
    if (!oldUser) {
      throw new Error('User not found');
    }

    // Check email uniqueness if being changed
    if (email) {
      const existingUser = await User.findOne({
        email,
        _id: { $ne: userId }
      });
      if (existingUser) {
        throw new Error('Email already exists');
      }
    }

    // Update user
    const user = await this.update(userId, { name, email, status });

    // Track changes
    const changes = {};
    if (name !== oldUser.name) changes.name = { from: oldUser.name, to: name };
    if (email !== oldUser.email) changes.email = { from: oldUser.email, to: email };
    if (status !== oldUser.status) changes.status = { from: oldUser.status, to: status };

    return {
      user: user.toJSON(),
      changes
    };
  }

  // Delete user
  async assignRole(userId, roleId) {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Validate role exists
    const role = await Role.findById(roleId);
    if (!role) {
      throw new Error('Invalid role ID');
    }

    const oldRole = user.role;
    user.role = roleId;
    await user.save();

    return {
      user: user.toJSON(),
      oldRole: oldRole.name,
      newRole: role.name
    };
  }

  // Add additional role to user
  async addAdditionalRole(userId, roleId) {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Validate role exists
    const role = await Role.findById(roleId);
    if (!role) {
      throw new Error('Invalid role ID');
    }

    // Check if role is already assigned
    if (user.role.toString() === roleId) {
      throw new Error('This role is already the primary role');
    }

    if (user.additionalRoles.includes(roleId)) {
      throw new Error('This role is already assigned as additional role');
    }

    user.additionalRoles.push(roleId);
    await user.save();

    return {
      user: user.toJSON(),
      addedRole: role.name
    };
  }

  // Remove additional role from user
  async removeAdditionalRole(userId, roleId) {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Check if role exists in additional roles
    if (!user.additionalRoles.includes(roleId)) {
      throw new Error('Role is not assigned as additional role');
    }

    const role = await Role.findById(roleId);
    user.additionalRoles = user.additionalRoles.filter(id => id.toString() !== roleId);
    await user.save();

    return {
      user: user.toJSON(),
      removedRole: role?.name || 'Unknown'
    };
  }

  // Delete user
  async deleteUser(userId, currentUserId) {
    // Prevent self-deletion
    if (userId === currentUserId) {
      throw new Error('You cannot delete your own account');
    }

    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      throw new Error('User not found');
    }

    return {
      deletedUser: {
        id: user._id,
        email: user.email,
        role: user.role.name
      }
    };
  }

  // Get pagination options
  async getUserStatistics() {
    // Basic user statistics
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

    // Role distribution
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

    // Recent registrations (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentRegistrations = await User.countDocuments({
      createdAt: { $gte: thirtyDaysAgo }
    });

    return {
      userStats: stats[0] || {
        totalUsers: 0,
        activeUsers: 0,
        inactiveUsers: 0,
        suspendedUsers: 0
      },
      roleDistribution,
      recentRegistrations
    };
  }

  // Search users by various criteria
  async searchUsers(searchParams) {
    const { query, status, roleId, limit = 10 } = searchParams;

    const filter = {};

    if (query) {
      filter.$or = [
        { name: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ];
    }

    if (status) filter.status = status;
    if (roleId) filter.role = roleId;

    return await User.find(filter)
      .limit(limit)
      .select('name email role status createdAt')
      .populate('role', 'name displayName color');
  }

  // Get users by role
  async getUsersByRole(roleId, options = {}) {
    const filter = { role: roleId };
    return await this.findWithPagination(filter, options);
  }
}

module.exports = UserService;