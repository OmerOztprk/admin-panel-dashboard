const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'login', 'logout', 'register', 'password_change', 'profile_update',
      'user_create', 'user_update', 'user_delete', 'failed_login',
      'account_locked', 'password_reset', 'role_change', 'status_change',
      'user_list_access', 'user_profile_access', 'user_stats_access',
      'access_denied'
    ]
  },
  resource: {
    type: String,
    required: true,
    enum: ['user', 'auth', 'system']
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