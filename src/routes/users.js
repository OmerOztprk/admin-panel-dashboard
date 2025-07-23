const express = require('express');
const userController = require('../controllers/userController');
const { protect, adminOnly, adminOrModerator } = require('../middlewares/auth');
const { 
  validateRegister, 
  validateUpdateUser,
  handleValidationErrors 
} = require('../utils/validation');

const router = express.Router();

// All routes are protected
router.use(protect);

// Admin/Moderator routes
router.get('/', adminOrModerator, userController.getAllUsers);
router.get('/stats', adminOnly, userController.getUserStats);
router.get('/:id', adminOrModerator, userController.getUser);

// Admin only routes
router.post('/', 
  adminOnly,
  validateRegister, 
  handleValidationErrors, 
  userController.createUser
);

router.put('/:id', 
  adminOrModerator,
  validateUpdateUser, 
  handleValidationErrors, 
  userController.updateUser
);

router.delete('/:id', adminOnly, userController.deleteUser);

module.exports = router;