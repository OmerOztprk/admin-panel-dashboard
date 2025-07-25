const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    required: [true, 'Role is required']
  },
  additionalRoles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended'],
    default: 'active'
  },
  avatar: {
    type: String,
    default: null
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ status: 1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual for all permissions (including additional roles)
userSchema.virtual('allPermissions').get(function() {
  const permissions = new Set();
  
  // Add permissions from primary role
  if (this.role && this.role.permissions) {
    this.role.permissions.forEach(perm => permissions.add(perm.name));
  }
  
  // Add permissions from additional roles
  if (this.additionalRoles) {
    this.additionalRoles.forEach(role => {
      if (role.permissions) {
        role.permissions.forEach(perm => permissions.add(perm.name));
      }
    });
  }
  
  return Array.from(permissions);
});

// Populate role and additional roles
userSchema.pre(/^find/, function(next) {
  this.populate({
    path: 'role',
    select: 'name displayName permissions level color icon'
  }).populate({
    path: 'additionalRoles',
    select: 'name displayName permissions level color icon'
  });
  next();
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(config.bcrypt.saltRounds);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Enhanced JWT token with permissions
userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      id: this._id, 
      email: this.email,
      role: this.role.name,
      permissions: this.allPermissions
    },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );
};

// Check if user has permission
userSchema.methods.hasPermission = function(permission) {
  return this.allPermissions.includes(permission);
};

// Check if user has any of the permissions
userSchema.methods.hasAnyPermission = function(permissions) {
  return permissions.some(perm => this.allPermissions.includes(perm));
};

// Check if user has all permissions
userSchema.methods.hasAllPermissions = function(permissions) {
  return permissions.every(perm => this.allPermissions.includes(perm));
};

// Handle failed login attempts
userSchema.methods.incLoginAttempts = function() {
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours

  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }
  
  return this.updateOne(updates);
};

// Reset login attempts on successful login
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 },
    $set: { lastLogin: new Date() }
  });
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.loginAttempts;
  delete userObject.lockUntil;
  return userObject;
};

module.exports = mongoose.model('User', userSchema);