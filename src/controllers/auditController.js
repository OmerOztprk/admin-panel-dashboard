const APIResponse = require('../utils/response');
const { auditService } = require('../services');

/**
 * Audit Controller
 * Handles HTTP requests and delegates business logic to AuditService
 */
class AuditController {

  // Get audit logs with filtering and pagination
  async getAuditLogs(req, res, next) {
    try {
      const userContext = {
        userId: req.user.id,
        role: req.user.role.name,
        level: req.user.role.level
      };

      const result = await auditService.getAuditLogs(req.query, userContext);

      APIResponse.success(res, result, 'Audit logs retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get user activity logs
  async getUserActivity(req, res, next) {
    try {
      const userContext = {
        userId: req.user.id,
        role: req.user.role.name,
        level: req.user.role.level
      };

      const result = await auditService.getUserActivity(
        req.params.userId, 
        req.query, 
        userContext
      );

      APIResponse.success(res, result, 'User activity retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get security events
  async getSecurityEvents(req, res, next) {
    try {
      const result = await auditService.getSecurityEvents(req.query);

      // Create audit log for viewing security events
      await auditService.createLog(
        req.user.id,
        'security_events_view',
        'audit',
        { 
          filters: req.query,
          eventCount: result.data.length,
          viewedBy: req.user.email
        },
        req,
        'success',
        'medium'
      );

      APIResponse.success(res, result, 'Security events retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Get audit statistics and analytics
  async getAuditStatistics(req, res, next) {
    try {
      const { dateFrom, dateTo } = req.query;
      const dateRange = { dateFrom, dateTo };
      
      const stats = await auditService.getAuditStatistics(dateRange);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'audit_statistics',
        'audit',
        { 
          dateRange,
          requestedBy: req.user.email,
          statsType: 'comprehensive_audit_overview'
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, stats, 'Audit statistics retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  // Clean old audit logs (Admin only)
  async cleanOldLogs(req, res, next) {
    try {
      const { daysToKeep = 90 } = req.body;
      
      const result = await auditService.cleanOldLogs(daysToKeep);

      // Create audit log for cleanup action
      await auditService.createLog(
        req.user.id,
        'audit_cleanup',
        'audit',
        { 
          deletedCount: result.deletedCount,
          daysKept: result.daysKept,
          cutoffDate: result.cutoffDate,
          cleanedBy: req.user.email
        },
        req,
        'success',
        'high'
      );

      APIResponse.success(res, result, 'Old audit logs cleaned successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export instance methods
const auditController = new AuditController();

module.exports = {
  getAuditLogs: auditController.getAuditLogs.bind(auditController),
  getUserActivity: auditController.getUserActivity.bind(auditController),
  getSecurityEvents: auditController.getSecurityEvents.bind(auditController),
  getAuditStatistics: auditController.getAuditStatistics.bind(auditController),
  cleanOldLogs: auditController.cleanOldLogs.bind(auditController)
};