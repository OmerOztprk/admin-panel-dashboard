const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Permission name is required'],
    unique: true,
    trim: true,
    lowercase: true
  },
  displayName: {
    type: String,
    required: [true, 'Display name is required'],
    trim: true
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: ['user', 'role', 'system', 'content', 'audit', 'settings'],
    default: 'system'
  },
  resource: {
    type: String,
    required: [true, 'Resource is required'],
    trim: true
  },
  action: {
    type: String,
    required: [true, 'Action is required'],
    enum: ['create', 'read', 'update', 'delete', 'manage', 'view'],
    default: 'read'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Compound index for unique resource-action combination
permissionSchema.index({ resource: 1, action: 1 }, { unique: true });
permissionSchema.index({ category: 1, isActive: 1 });

// Generate permission name automatically BEFORE validation
permissionSchema.pre('validate', function(next) {
  if (!this.name && this.resource && this.action) {
    this.name = `${this.resource}:${this.action}`;
  }
  next();
});

module.exports = mongoose.model('Permission', permissionSchema);