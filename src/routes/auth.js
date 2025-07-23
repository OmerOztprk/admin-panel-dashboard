const express = require('express');
const authController = require('../controllers/authController');
const { protect } = require('../middlewares/auth');
const { 
  validateRegister, 
  validateLogin, 
  validateUpdateUser,
  validateChangePassword,
  handleValidationErrors 
} = require('../utils/validation');

const router = express.Router();

// Public routes
router.post('/register', 
  validateRegister, 
  handleValidationErrors, 
  authController.register
);

router.post('/login', 
  validateLogin, 
  handleValidationErrors, 
  authController.login
);

// Protected routes
router.use(protect); // All routes after this middleware are protected

router.get('/profile', authController.getProfile);

router.put('/profile', 
  validateUpdateUser, 
  handleValidationErrors, 
  authController.updateProfile
);

router.put('/change-password', 
  validateChangePassword, 
  handleValidationErrors, 
  authController.changePassword
);

router.post('/logout', authController.logout);
router.post('/logout-all', authController.forceLogoutAll);

module.exports = router;