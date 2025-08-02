const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
    default: null // null allowed for anonymous actions
  },
  action: {
    type: String,
    required: true,
    enum: [
      // Auth actions
      'login', 'logout', 'register', 'password_change', 'profile_update', 'failed_login',
      
      // User actions
      'create', 'read', 'update', 'delete', 'list', 'view', 'search', 'statistics',
      
      // Role actions
      'role_change', 'permission_assign', 'additional_role_add', 'additional_role_remove',
      
      // System actions
      'account_locked', 'password_reset', 'status_change', 'access_denied',
      'user_list_access', 'user_profile_access', 'user_stats_access',
      
      // Audit actions
      'security_events_view', 'audit_statistics', 'audit_cleanup',
      
      // General actions
      'categories', 'hierarchy', 'bulk_update'
    ]
  },
  resource: {
    type: String,
    required: true,
    enum: ['user', 'auth', 'system', 'role', 'permission', 'audit', 'content', 'settings']
  },
  resourceId: {
    type: String,
    default: null
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String,
    required: true,
    index: true
  },
  userAgent: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['success', 'failure', 'warning'],
    default: 'success'
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  }
}, {
  timestamps: true
});

// Indexes for performance and TTL
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ ipAddress: 1, createdAt: -1 });
auditLogSchema.index({ status: 1, severity: 1, createdAt: -1 });

// TTL index - logs will be deleted after 90 days
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

module.exports = mongoose.model('AuditLog', auditLogSchema);