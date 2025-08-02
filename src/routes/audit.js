const express = require('express');
const auditController = require('../controllers/auditController');
const { protect, adminOnly, adminOrModerator } = require('../middlewares/auth');

const router = express.Router();

// All routes are protected
router.use(protect);

// Audit management routes
router.get('/logs', adminOnly, auditController.getAuditLogs);
router.get('/security-events', adminOnly, auditController.getSecurityEvents);
router.get('/user/:userId', adminOrModerator, auditController.getUserActivity);

module.exports = router;