/**
 * Service Layer Export Index
 * Tüm service'leri merkezi olarak export eder
 */

const AuthService = require('./authService');
const UserService = require('./userService');
const RoleService = require('./roleService');
const PermissionService = require('./permissionService');
const AuditService = require('./auditService');

// Service instances
const authService = new AuthService();
const userService = new UserService();
const roleService = new RoleService();
const permissionService = new PermissionService();
const auditService = new AuditService();

module.exports = {
  // Service classes
  AuthService,
  UserService,
  RoleService,
  PermissionService,
  AuditService,
  
  // Service instances
  authService,
  userService,
  roleService,
  permissionService,
  auditService
};