const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Role name is required'],
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
  permissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],
  level: {
    type: Number,
    required: [true, 'Role level is required'],
    min: 1,
    max: 100,
    default: 1
  },
  isSystemRole: {
    type: Boolean,
    default: false // System roles cannot be deleted
  },
  isActive: {
    type: Boolean,
    default: true
  },
  color: {
    type: String,
    default: '#6B7280' // Tailwind gray-500
  },
  icon: {
    type: String,
    default: 'user' // FontAwesome icon name
  }
}, {
  timestamps: true
});

// Indexes
roleSchema.index({ name: 1 });
roleSchema.index({ level: 1 });
roleSchema.index({ isActive: 1 });

// Virtual for permission count
roleSchema.virtual('permissionCount', {
  ref: 'Permission',
  localField: 'permissions',
  foreignField: '_id',
  count: true
});

// Populate permissions by default
roleSchema.pre(/^find/, function(next) {
  this.populate({
    path: 'permissions',
    select: 'name displayName category resource action'
  });
  next();
});

module.exports = mongoose.model('Role', roleSchema);