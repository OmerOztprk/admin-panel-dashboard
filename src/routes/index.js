const express = require('express');
const authRoutes = require('./auth');
const userRoutes = require('./users');
const roleRoutes = require('./roles');
const permissionRoutes = require('./permissions');
const auditRoutes = require('./audit');

const router = express.Router();

// API Routes
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/roles', roleRoutes);
router.use('/permissions', permissionRoutes);
router.use('/audit', auditRoutes);

// API Info endpoint
router.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: req.t('welcome'),
    version: '1.0.0',
    features: [
      'JWT Authentication with Token Blacklisting',
      'Dynamic RBAC System',
      'Permission-based Access Control',
      'Multi-role Support',
      'Comprehensive Audit Logging',
      'Account Security (Locking, Rate Limiting)',
      'Real-time User Statistics',
      'Role Hierarchy System'
    ],
    endpoints: {
      auth: {
        base: '/api/auth',
        endpoints: [
          'POST /register - Register new user',
          'POST /login - User login',
          'GET /profile - Get current user profile',
          'PUT /profile - Update current user profile',
          'PUT /change-password - Change password',
          'POST /logout - Logout current session',
          'POST /logout-all - Logout all sessions'
        ]
      },
      users: {
        base: '/api/users',
        endpoints: [
          'GET / - Get all users (user:read)',
          'GET /stats - Get user statistics (user:read)',
          'GET /:id - Get user by ID (user:read)',
          'POST / - Create new user (user:create)',
          'PUT /:id - Update user (user:update)',
          'PUT /:id/role - Assign role to user (user:update)',
          'PUT /:id/additional-roles - Add additional role (user:update)',
          'DELETE /:id/additional-roles/:roleId - Remove additional role (user:update)',
          'DELETE /:id - Delete user (user:delete)'
        ]
      },
      roles: {
        base: '/api/roles',
        endpoints: [
          'GET / - Get all roles (user:read)',
          'GET /stats/overview - Get role statistics (system:manage)',
          'GET /:id - Get role by ID (user:read)',
          'POST / - Create new role (system:manage)',
          'PUT /:id - Update role (system:manage)',
          'PUT /:id/permissions - Assign permissions to role (system:manage)',
          'DELETE /:id - Delete role (Super Admin only)'
        ]
      },
      permissions: {
        base: '/api/permissions',
        endpoints: [
          'GET / - Get all permissions (system:manage)',
          'GET /categories - Get permission categories (system:manage)',
          'GET /:id - Get permission by ID (system:manage)',
          'POST / - Create new permission (system:manage)',
          'PUT /:id - Update permission (system:manage)',
          'DELETE /:id - Delete permission (system:manage)'
        ]
      },
      audit: {
        base: '/api/audit',
        endpoints: [
          'GET /logs - Get all audit logs (system:manage)',
          'GET /user/:userId - Get user activity',
          'GET /security-events - Get security events (system:manage)'
        ]
      }
    },
    permissions: {
      categories: ['user', 'role', 'system', 'content', 'audit', 'settings'],
      actions: ['create', 'read', 'update', 'delete', 'manage', 'view'],
      examples: [
        'user:create - Can create new users',
        'user:read - Can view users',
        'user:update - Can update users',
        'user:delete - Can delete users',
        'system:manage - Full system management access',
        'audit:view - Can view audit logs'
      ]
    }
  });
});

module.exports = router;