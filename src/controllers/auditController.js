const AuditLog = require('../models/AuditLog');
const APIResponse = require('../utils/response');

// Get audit logs (Admin only)
exports.getAuditLogs = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    
    // Filters
    const userId = req.query.userId;
    const action = req.query.action;
    const resource = req.query.resource;
    const status = req.query.status;
    const severity = req.query.severity;
    const ipAddress = req.query.ipAddress;
    const dateFrom = req.query.dateFrom;
    const dateTo = req.query.dateTo;

    // Build filter object
    const filter = {};
    if (userId) filter.userId = userId;
    if (action) filter.action = action;
    if (resource) filter.resource = resource;
    if (status) filter.status = status;
    if (severity) filter.severity = severity;
    if (ipAddress) filter.ipAddress = ipAddress;
    
    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo) filter.createdAt.$lte = new Date(dateTo);
    }

    // Calculate skip
    const skip = (page - 1) * limit;

    // Get audit logs with pagination
    const auditLogs = await AuditLog.find(filter)
      .populate('userId', 'name email role')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit);

    // Get total count
    const total = await AuditLog.countDocuments(filter);

    // Calculate pagination info
    const totalPages = Math.ceil(total / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    APIResponse.success(res, {
      auditLogs,
      pagination: {
        currentPage: page,
        totalPages,
        totalLogs: total,
        hasNextPage,
        hasPrevPage,
        limit
      }
    }, 'Audit logs retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Get user activity (Admin/Moderator or own activity)
exports.getUserActivity = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    
    // Check if user can access this data
    if (req.user.role === 'user' && userId !== req.user.id.toString()) {
      return APIResponse.forbidden(res, 'You can only view your own activity');
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const action = req.query.action;

    const filter = { userId };
    if (action) filter.action = action;

    const skip = (page - 1) * limit;

    const activities = await AuditLog.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await AuditLog.countDocuments(filter);

    APIResponse.success(res, {
      activities,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalActivities: total,
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
        limit
      }
    }, 'User activity retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Get security events (Admin only)
exports.getSecurityEvents = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    // Security related events
    const securityActions = [
      'failed_login', 'account_locked', 'password_change', 
      'role_change', 'status_change', 'force_logout'
    ];

    const filter = {
      $or: [
        { action: { $in: securityActions } },
        { status: 'failure' },
        { severity: { $in: ['high', 'critical'] } }
      ]
    };

    const skip = (page - 1) * limit;

    const securityEvents = await AuditLog.find(filter)
      .populate('userId', 'name email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await AuditLog.countDocuments(filter);

    APIResponse.success(res, {
      securityEvents,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalEvents: total,
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
        limit
      }
    }, 'Security events retrieved successfully');

  } catch (error) {
    next(error);
  }
};