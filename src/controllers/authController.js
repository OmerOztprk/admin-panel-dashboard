const mongoose = require('mongoose');
const APIResponse = require('../utils/response');
const { handleValidationErrors } = require('../utils/validation');
const { authService, auditService } = require('../services');

/**
 * Authentication Controller
 * Handles HTTP requests and delegates business logic to AuthService
 */
class AuthController {

  // Register new user
  async register(req, res, next) {
    try {
      // Handle validation errors
      handleValidationErrors(req, res, () => {});

      const result = await authService.register(req.body, req);

      // Create audit log
      await auditService.createLog(
        result.user.id,
        'register',
        'user',
        { 
          email: result.user.email,
          role: result.role.name,
          registration_method: 'standard'
        },
        req,
        'success',
        'low'
      );

      APIResponse.created(res, {
        user: result.user,
        token: result.token
      }, req.t('auth.userCreated'));

    } catch (error) {
      // Create audit log for failed registration
      await auditService.createLog(
        null,
        'register',
        'user',
        { 
          email: req.body.email,
          error: error.message
        },
        req,
        'failure',
        'medium'
      );

      next(error);
    }
  }

  // Login user
  async login(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await authService.login(req.body, req);

      // Create audit log for successful login
      await auditService.createLog(
        result.user.id,
        'login',
        'auth',
        { 
          login_method: 'password',
          user_agent: req.get('User-Agent'),
          last_login: result.lastLogin
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, {
        user: result.user,
        token: result.token
      }, req.t('auth.loginSuccess'));

    } catch (error) {
      // Create audit log for failed login
      const auditData = error.auditData || { 
        email: req.body.email,
        error: error.message 
      };
      
      await auditService.createLog(
        auditData.userId || null,
        'failed_login',
        'auth',
        auditData,
        req,
        'failure',
        error.code === 'ACCOUNT_LOCKED' ? 'high' : 'medium'
      );

      next(error);
    }
  }

  // Logout user
  async logout(req, res, next) {
    try {
      const result = await authService.logout(req.token, req.user.id, req);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'logout',
        'auth',
        { 
          logout_method: 'manual',
          token_expires_at: result.tokenExpiration
        },
        req,
        'success',
        'low'
      );

      APIResponse.success(res, null, req.t('auth.logoutSuccess'));
    } catch (error) {
      next(error);
    }
  }

  // Get current user profile
  async getProfile(req, res, next) {
    try {
      // User is already available from auth middleware
      const user = req.user;
      
      APIResponse.success(res, { user }, 'Profile retrieved successfully');

    } catch (error) {
      next(error);
    }
  }

  // Update user profile
  async updateProfile(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await authService.updateProfile(req.user.id, req.body);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'profile_update',
        'user',
        { 
          changes: result.changes,
          updated_by: 'self'
        },
        req,
        'success',
        'low'
      );

      APIResponse.updated(res, { user: result.user }, req.t('auth.userUpdated'));

    } catch (error) {
      next(error);
    }
  }

  // Change password
  async changePassword(req, res, next) {
    try {
      handleValidationErrors(req, res, () => {});

      const result = await authService.changePassword(
        req.user.id, 
        req.body, 
        req.token, 
        req
      );

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'password_change',
        'auth',
        { 
          method: 'self_change',
          tokens_invalidated: result.tokenInvalidated
        },
        req,
        'success',
        'medium'
      );

      APIResponse.success(res, null, req.t('auth.passwordChanged'));

    } catch (error) {
      // Create audit log for failed password change
      const auditData = error.auditData || { 
        error: error.message 
      };
      
      await auditService.createLog(
        req.user.id,
        'password_change',
        'auth',
        auditData,
        req,
        'failure',
        'high'
      );

      next(error);
    }
  }

  // Force logout all sessions
  async forceLogoutAll(req, res, next) {
    try {
      const result = await authService.logout(req.token, req.user.id, req);

      // Create audit log
      await auditService.createLog(
        req.user.id,
        'logout',
        'auth',
        { 
          logout_method: 'force_all_sessions',
          initiated_by: 'user',
          note: 'In a production system, this would invalidate all user tokens'
        },
        req,
        'success',
        'medium'
      );

      APIResponse.success(res, null, 'All sessions logged out successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export instance methods
const authController = new AuthController();

module.exports = {
  register: authController.register.bind(authController),
  login: authController.login.bind(authController),
  logout: authController.logout.bind(authController),
  getProfile: authController.getProfile.bind(authController),
  updateProfile: authController.updateProfile.bind(authController),
  changePassword: authController.changePassword.bind(authController),
  forceLogoutAll: authController.forceLogoutAll.bind(authController)
};