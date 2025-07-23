const mongoose = require('mongoose');

const blacklistedTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  reason: {
    type: String,
    enum: ['logout', 'force_logout', 'security_breach', 'password_change'],
    default: 'logout'
  },
  userAgent: {
    type: String,
    default: null
  },
  ipAddress: {
    type: String,
    default: null
  },
  expiresAt: {
    type: Date,
    required: true,
    expires: 0 // MongoDB otomatik silecek
  }
}, {
  timestamps: true
});

// Compound index for better performance
blacklistedTokenSchema.index({ token: 1, userId: 1 });
blacklistedTokenSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('BlacklistedToken', blacklistedTokenSchema);