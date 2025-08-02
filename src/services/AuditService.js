const AuditLog = require('../models/AuditLog');
const User = require('../models/User');
const BaseService = require('./BaseService');

/**
 * Audit Service
 * Handles all audit logging and security monitoring business logic
 */
class AuditService extends BaseService {
  constructor() {
    super(AuditLog);
  }

  // Create audit log entry
  async createLog(userId, action, resource, details = {}, req, status = 'success', severity = 'low') {
    try {
      const auditData = {
        userId: userId || null, // Allow null for anonymous/system actions
        action,
        resource,
        details,
        status,
        severity,
        ipAddress: req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date()
      };

      // Add request path and method if available
      if (req.path) auditData.details.requestPath = req.path;
      if (req.method) auditData.details.requestMethod = req.method;

      return await AuditLog.create(auditData);
    } catch (error) {
      console.error('Audit log creation failed:', error.message);
      // Don't throw error to prevent breaking the main operation
      return null;
    }
  }

  // Get audit logs with pagination and filtering
  async getAuditLogs(query, userContext) {
    const {
      userId, action, resource, status, severity, ipAddress,
      dateFrom, dateTo, userRole
    } = query;

    // Build filter object
    const filter = {};

    // Access control - users can only see their own logs unless admin+
    if (userContext.role === 'user') {
      filter.userId = userContext.userId;
    } else if (userId) {
      filter.userId = userId;
    }

    if (action) filter.action = action;
    if (resource) filter.resource = resource;
    if (status) filter.status = status;
    if (severity) filter.severity = severity;
    if (ipAddress) filter.ipAddress = ipAddress;

    // Date range filtering
    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo) filter.createdAt.$lte = new Date(dateTo);
    }

    const result = await this.findWithPagination(filter, query);

    // Populate user information for admin+ users
    if (userContext.role !== 'user') {
      const populatedLogs = await AuditLog.populate(result.data, {
        path: 'userId',
        select: 'name email role',
        populate: {
          path: 'role',
          select: 'name displayName color'
        }
      });
      result.data = populatedLogs;
    }

    return result;
  }

  // Get user activity with pagination and filtering
  async getUserActivity(userId, query, userContext) {
    // Access control
    if (userContext.role === 'user' && userId !== userContext.userId) {
      throw new Error('Access denied. You can only view your own activity.');
    }

    const { action, status, dateFrom, dateTo } = query;

    const filter = { userId };
    if (action) filter.action = action;
    if (status) filter.status = status;

    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo) filter.createdAt.$lte = new Date(dateTo);
    }

    const result = await this.findWithPagination(filter, query);

    // Get user info
    const user = await User.findById(userId)
      .select('name email role')
      .populate('role', 'name displayName');

    // Activity summary
    const activitySummary = await this.getUserActivitySummary(userId, dateFrom, dateTo);

    return {
      ...result,
      user,
      activitySummary
    };
  }

  // Get security-related audit logs
  async getSecurityEvents(query) {
    // Security-related actions
    const securityActions = [
      'failed_login', 'account_locked', 'password_change',
      'role_change', 'status_change', 'force_logout',
      'suspicious_activity', 'access_denied'
    ];

    const filter = {
      $or: [
        { action: { $in: securityActions } },
        { status: 'failure' },
        { severity: { $in: ['high', 'critical'] } }
      ]
    };

    // Additional filters
    if (query.severity) {
      filter.severity = query.severity;
    }

    if (query.dateFrom || query.dateTo) {
      filter.createdAt = {};
      if (query.dateFrom) filter.createdAt.$gte = new Date(query.dateFrom);
      if (query.dateTo) filter.createdAt.$lte = new Date(query.dateTo);
    }

    const result = await this.findWithPagination(filter, query);

    // Populate user information
    const populatedEvents = await AuditLog.populate(result.data, {
      path: 'userId',
      select: 'name email role status',
      populate: {
        path: 'role',
        select: 'name displayName'
      }
    });

    return {
      ...result,
      data: populatedEvents
    };
  }

  // Get audit statistics
  async getAuditStatistics(dateRange = {}) {
    const { dateFrom, dateTo } = dateRange;

    // Build date filter
    const dateFilter = {};
    if (dateFrom || dateTo) {
      dateFilter.createdAt = {};
      if (dateFrom) dateFilter.createdAt.$gte = new Date(dateFrom);
      if (dateTo) dateFilter.createdAt.$lte = new Date(dateTo);
    }

    // Basic statistics
    const basicStats = await AuditLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: null,
          totalLogs: { $sum: 1 },
          successfulActions: {
            $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
          },
          failedActions: {
            $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
          },
          criticalEvents: {
            $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
          },
          highSeverityEvents: {
            $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] }
          },
          uniqueUsers: { $addToSet: '$userId' },
          uniqueIPs: { $addToSet: '$ipAddress' }
        }
      },
      {
        $project: {
          totalLogs: 1,
          successfulActions: 1,
          failedActions: 1,
          criticalEvents: 1,
          highSeverityEvents: 1,
          uniqueUsers: { $size: '$uniqueUsers' },
          uniqueIPs: { $size: '$uniqueIPs' },
          successRate: {
            $multiply: [
              { $divide: ['$successfulActions', '$totalLogs'] },
              100
            ]
          }
        }
      }
    ]);

    // Action distribution
    const actionStats = await AuditLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 },
          successCount: {
            $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
          },
          failureCount: {
            $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
          }
        }
      },
      {
        $sort: { count: -1 }
      },
      { $limit: 10 }
    ]);

    // Resource distribution
    const resourceStats = await AuditLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: '$resource',
          count: { $sum: 1 },
          uniqueUsers: { $addToSet: '$userId' }
        }
      },
      {
        $project: {
          resource: '$_id',
          count: 1,
          uniqueUsers: { $size: '$uniqueUsers' }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    // Hourly activity (last 24 hours)
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const hourlyActivity = await AuditLog.aggregate([
      {
        $match: {
          createdAt: { $gte: twentyFourHoursAgo }
        }
      },
      {
        $group: {
          _id: {
            hour: { $hour: '$createdAt' },
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.date': 1, '_id.hour': 1 }
      }
    ]);

    // Top IP addresses by activity
    const topIPs = await AuditLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: '$ipAddress',
          count: { $sum: 1 },
          uniqueUsers: { $addToSet: '$userId' },
          failureCount: {
            $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
          }
        }
      },
      {
        $project: {
          ipAddress: '$_id',
          count: 1,
          uniqueUsers: { $size: '$uniqueUsers' },
          failureCount: 1,
          suspiciousScore: {
            $multiply: [
              { $divide: ['$failureCount', '$count'] },
              100
            ]
          }
        }
      },
      {
        $sort: { count: -1 }
      },
      { $limit: 10 }
    ]);

    return {
      basicStats: basicStats[0] || {
        totalLogs: 0,
        successfulActions: 0,
        failedActions: 0,
        criticalEvents: 0,
        highSeverityEvents: 0,
        uniqueUsers: 0,
        uniqueIPs: 0,
        successRate: 0
      },
      actionDistribution: actionStats,
      resourceDistribution: resourceStats,
      hourlyActivity,
      topIPAddresses: topIPs,
      dateRange: {
        from: dateFrom || null,
        to: dateTo || null
      }
    };
  }

  // Get user activity summary
  async getUserActivitySummary(userId, dateFrom, dateTo) {
    const dateFilter = { userId };
    if (dateFrom || dateTo) {
      dateFilter.createdAt = {};
      if (dateFrom) dateFilter.createdAt.$gte = new Date(dateFrom);
      if (dateTo) dateFilter.createdAt.$lte = new Date(dateTo);
    }

    const summary = await AuditLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: null,
          totalActions: { $sum: 1 },
          successfulActions: {
            $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
          },
          failedActions: {
            $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
          },
          uniqueResources: { $addToSet: '$resource' },
          lastActivity: { $max: '$createdAt' },
          firstActivity: { $min: '$createdAt' }
        }
      }
    ]);

    // Most frequent actions
    const frequentActions = await AuditLog.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      { $limit: 5 }
    ]);

    return {
      ...summary[0],
      uniqueResources: summary[0]?.uniqueResources?.length || 0,
      frequentActions
    };
  }
  
  // Clean old audit logs
  async cleanOldLogs(daysToKeep = 90) {
    const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);

    const deleteResult = await AuditLog.deleteMany({
      createdAt: { $lt: cutoffDate }
    });

    return {
      deletedCount: deleteResult.deletedCount,
      cutoffDate,
      daysKept: daysToKeep
    };
  }
}

module.exports = AuditService;