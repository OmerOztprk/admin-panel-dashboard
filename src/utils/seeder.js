const mongoose = require('mongoose');
const Permission = require('../models/Permission');
const Role = require('../models/Role');
const User = require('../models/User');
const config = require('../config');

// Default permissions - name field'ı da ekliyoruz
const defaultPermissions = [
  // User permissions
  { 
    name: 'user:create',
    displayName: 'Create Users', 
    description: 'Create new user accounts', 
    category: 'user', 
    resource: 'user', 
    action: 'create' 
  },
  { 
    name: 'user:read',
    displayName: 'View Users', 
    description: 'View user profiles and lists', 
    category: 'user', 
    resource: 'user', 
    action: 'read' 
  },
  { 
    name: 'user:update',
    displayName: 'Update Users', 
    description: 'Update user information and settings', 
    category: 'user', 
    resource: 'user', 
    action: 'update' 
  },
  { 
    name: 'user:delete',
    displayName: 'Delete Users', 
    description: 'Delete user accounts', 
    category: 'user', 
    resource: 'user', 
    action: 'delete' 
  },
  { 
    name: 'user:manage',
    displayName: 'Manage Users', 
    description: 'Full user management access', 
    category: 'user', 
    resource: 'user', 
    action: 'manage' 
  },
  
  // Role permissions
  { 
    name: 'role:create',
    displayName: 'Create Roles', 
    description: 'Create new roles', 
    category: 'role', 
    resource: 'role', 
    action: 'create' 
  },
  { 
    name: 'role:read',
    displayName: 'View Roles', 
    description: 'View roles and permissions', 
    category: 'role', 
    resource: 'role', 
    action: 'read' 
  },
  { 
    name: 'role:update',
    displayName: 'Update Roles', 
    description: 'Update role permissions and settings', 
    category: 'role', 
    resource: 'role', 
    action: 'update' 
  },
  { 
    name: 'role:delete',
    displayName: 'Delete Roles', 
    description: 'Delete roles', 
    category: 'role', 
    resource: 'role', 
    action: 'delete' 
  },
  { 
    name: 'role:manage',
    displayName: 'Manage Roles', 
    description: 'Full role management access', 
    category: 'role', 
    resource: 'role', 
    action: 'manage' 
  },
  
  // System permissions
  { 
    name: 'system:manage',
    displayName: 'System Management', 
    description: 'Full system administration access', 
    category: 'system', 
    resource: 'system', 
    action: 'manage' 
  },
  { 
    name: 'system:view',
    displayName: 'View System Stats', 
    description: 'View system statistics and health', 
    category: 'system', 
    resource: 'system', 
    action: 'view' 
  },
  
  // Audit permissions
  { 
    name: 'audit:view',
    displayName: 'View Audit Logs', 
    description: 'View audit logs and user activities', 
    category: 'audit', 
    resource: 'audit', 
    action: 'view' 
  },
  { 
    name: 'audit:manage',
    displayName: 'Manage Audit Logs', 
    description: 'Full audit log management', 
    category: 'audit', 
    resource: 'audit', 
    action: 'manage' 
  },
  
  // Content permissions
  { 
    name: 'content:create',
    displayName: 'Create Content', 
    description: 'Create new content', 
    category: 'content', 
    resource: 'content', 
    action: 'create' 
  },
  { 
    name: 'content:read',
    displayName: 'View Content', 
    description: 'View content', 
    category: 'content', 
    resource: 'content', 
    action: 'read' 
  },
  { 
    name: 'content:update',
    displayName: 'Update Content', 
    description: 'Update existing content', 
    category: 'content', 
    resource: 'content', 
    action: 'update' 
  },
  { 
    name: 'content:delete',
    displayName: 'Delete Content', 
    description: 'Delete content', 
    category: 'content', 
    resource: 'content', 
    action: 'delete' 
  },
  
  // Settings permissions
  { 
    name: 'settings:view',
    displayName: 'View Settings', 
    description: 'View application settings', 
    category: 'settings', 
    resource: 'settings', 
    action: 'view' 
  },
  { 
    name: 'settings:manage',
    displayName: 'Manage Settings', 
    description: 'Update application settings', 
    category: 'settings', 
    resource: 'settings', 
    action: 'manage' 
  }
];

// Seeder function
const seedDatabase = async () => {
  try {
    console.log('🌱 Starting database seeding...');

    // Connect to database
    await mongoose.connect(config.mongodb.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Clear existing data
    console.log('🧹 Clearing existing data...');
    await Permission.deleteMany({});
    await Role.deleteMany({});
    await User.deleteMany({});

    // Create permissions one by one to ensure middleware runs
    console.log('📋 Creating permissions...');
    const createdPermissions = [];
    
    for (const permData of defaultPermissions) {
      const permission = await Permission.create(permData);
      createdPermissions.push(permission);
    }
    
    console.log(`✅ Created ${createdPermissions.length} permissions`);

    // Create default roles
    console.log('🎭 Creating default roles...');

    // Super Admin Role (Level 100)
    const superAdminPermissions = createdPermissions.map(p => p._id);
    const superAdminRole = await Role.create({
      name: 'super_admin',
      displayName: 'Super Administrator',
      description: 'Full system access with all permissions',
      permissions: superAdminPermissions,
      level: 100,
      isSystemRole: true,
      color: '#DC2626', // Red
      icon: 'crown'
    });
    console.log('✅ Created Super Admin role');

    // Admin Role (Level 80)
    const adminPermissions = createdPermissions.filter(p => 
      p.name !== 'system:manage'
    ).map(p => p._id);
    const adminRole = await Role.create({
      name: 'admin',
      displayName: 'Administrator',
      description: 'Administrative access with most permissions',
      permissions: adminPermissions,
      level: 80,
      isSystemRole: true,
      color: '#EF4444', // Red-500
      icon: 'shield-alt'
    });
    console.log('✅ Created Admin role');

    // Moderator Role (Level 50)
    const moderatorPermissions = createdPermissions.filter(p => 
      ['user:read', 'user:update', 'content:create', 'content:read', 'content:update', 'audit:view'].includes(p.name)
    ).map(p => p._id);
    const moderatorRole = await Role.create({
      name: 'moderator',
      displayName: 'Moderator',
      description: 'Content moderation and user management',
      permissions: moderatorPermissions,
      level: 50,
      isSystemRole: true,
      color: '#F59E0B', // Yellow-500
      icon: 'user-shield'
    });
    console.log('✅ Created Moderator role');

    // Editor Role (Level 30)
    const editorPermissions = createdPermissions.filter(p => 
      ['content:create', 'content:read', 'content:update', 'user:read'].includes(p.name)
    ).map(p => p._id);
    const editorRole = await Role.create({
      name: 'editor',
      displayName: 'Editor',
      description: 'Content creation and editing',
      permissions: editorPermissions,
      level: 30,
      isSystemRole: true,
      color: '#10B981', // Green-500
      icon: 'edit'
    });
    console.log('✅ Created Editor role');

    // User Role (Level 10)
    const userPermissions = createdPermissions.filter(p => 
      ['content:read'].includes(p.name)
    ).map(p => p._id);
    const userRole = await Role.create({
      name: 'user',
      displayName: 'User',
      description: 'Basic user access',
      permissions: userPermissions,
      level: 10,
      isSystemRole: true,
      color: '#6B7280', // Gray-500
      icon: 'user'
    });
    console.log('✅ Created User role');

    // Create default super admin user (User model'in save middleware'i password'ı hash edecek)
    console.log('👤 Creating default super admin user...');
    const superAdminUser = await User.create({
      name: 'Super Administrator',
      email: 'superadmin@adminpanel.com',
      password: 'SuperAdmin123!', // Raw password - User model hash edecek
      role: superAdminRole._id,
      status: 'active'
    });
    console.log('✅ Created Super Admin user');

    // Create default admin user
    console.log('👤 Creating default admin user...');
    const adminUser = await User.create({
      name: 'Administrator',
      email: 'admin@adminpanel.com',
      password: 'Admin123!', // Raw password - User model hash edecek
      role: adminRole._id,
      status: 'active'
    });
    console.log('✅ Created Admin user');

    // Create test moderator user
    console.log('👤 Creating test moderator user...');
    const moderatorUser = await User.create({
      name: 'Test Moderator',
      email: 'moderator@adminpanel.com',
      password: 'Moderator123!',
      role: moderatorRole._id,
      status: 'active'
    });
    console.log('✅ Created Moderator user');

    console.log('\n🎉 Database seeding completed successfully!');
    console.log('\n📋 Default Accounts Created:');
    console.log('Super Admin: superadmin@adminpanel.com / SuperAdmin123!');
    console.log('Admin: admin@adminpanel.com / Admin123!');
    console.log('Moderator: moderator@adminpanel.com / Moderator123!');
    console.log('\n🔐 Default Roles Created:');
    console.log(`- Super Administrator (Level 100) - ID: ${superAdminRole._id}`);
    console.log(`- Administrator (Level 80) - ID: ${adminRole._id}`);
    console.log(`- Moderator (Level 50) - ID: ${moderatorRole._id}`);
    console.log(`- Editor (Level 30) - ID: ${editorRole._id}`);
    console.log(`- User (Level 10) - ID: ${userRole._id}`);
    
    console.log('\n📊 Permission Summary:');
    console.log(`- Total Permissions: ${createdPermissions.length}`);
    console.log('- Categories: User, Role, System, Content, Audit, Settings');
    console.log('- Actions: create, read, update, delete, manage, view');
    
    console.log('\n💡 Usage Examples:');
    console.log('Register with role ID:');
    console.log(`{
  "name": "Test User",
  "email": "test@example.com", 
  "password": "TestUser123!",
  "role": "${userRole._id}"
}`);

    process.exit(0);
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  }
};

// Run seeder if called directly
if (require.main === module) {
  seedDatabase();
}

module.exports = seedDatabase;