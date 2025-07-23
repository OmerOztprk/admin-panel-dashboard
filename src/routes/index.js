const express = require('express');
const authRoutes = require('./auth');
const userRoutes = require('./users');
const auditRoutes = require('./audit');

const router = express.Router();

// API Routes
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/audit', auditRoutes);

// API Info endpoint
router.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: req.t('welcome'),
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      users: '/api/users',
      audit: '/api/audit'
    },
    documentation: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        profile: 'GET /api/auth/profile',
        updateProfile: 'PUT /api/auth/profile',
        changePassword: 'PUT /api/auth/change-password',
        logout: 'POST /api/auth/logout',
        logoutAll: 'POST /api/auth/logout-all'
      },
      users: {
        getAll: 'GET /api/users',
        getOne: 'GET /api/users/:id',
        create: 'POST /api/users',
        update: 'PUT /api/users/:id',
        delete: 'DELETE /api/users/:id',
        stats: 'GET /api/users/stats'
      },
      audit: {
        logs: 'GET /api/audit/logs',
        userActivity: 'GET /api/audit/user/:userId',
        securityEvents: 'GET /api/audit/security-events'
      }
    }
  });
});

module.exports = router;