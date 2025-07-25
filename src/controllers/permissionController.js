const Permission = require('../models/Permission');
const APIResponse = require('../utils/response');
const { createAuditLog } = require('../middlewares/auth');

// Get all permissions
exports.getAllPermissions = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const category = req.query.category;
    const isActive = req.query.isActive;
    const search = req.query.search;

    // Build filter
    const filter = {};
    if (category) filter.category = category;
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { displayName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const permissions = await Permission.find(filter)
      .sort({ category: 1, name: 1 })
      .skip(skip)
      .limit(limit);

    const total = await Permission.countDocuments(filter);

    // Log access
    await createAuditLog(
      req.user._id,
      'permission_list_access',
      'system',
      { total_returned: permissions.length, filters: { category, isActive, search } },
      req,
      'success',
      'low'
    );

    APIResponse.success(res, {
      permissions,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalPermissions: total,
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
        limit
      }
    }, 'Permissions retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Get permission by ID
exports.getPermission = async (req, res, next) => {
  try {
    const permission = await Permission.findById(req.params.id);
    
    if (!permission) {
      return APIResponse.notFound(res, 'Permission not found');
    }

    APIResponse.success(res, { permission }, 'Permission retrieved successfully');

  } catch (error) {
    next(error);
  }
};

// Create new permission
exports.createPermission = async (req, res, next) => {
  try {
    const { displayName, description, category, resource, action } = req.body;

    const permission = await Permission.create({
      displayName,
      description,
      category,
      resource,
      action
    });

    // Log creation
    await createAuditLog(
      req.user._id,
      'permission_create',
      'system',
      { 
        created_permission: permission._id,
        name: permission.name,
        resource: permission.resource,
        action: permission.action
      },
      req,
      'success',
      'medium'
    );

    APIResponse.created(res, { permission }, 'Permission created successfully');

  } catch (error) {
    next(error);
  }
};

// Update permission
exports.updatePermission = async (req, res, next) => {
  try {
    const { displayName, description, category, isActive } = req.body;
    const oldPermission = await Permission.findById(req.params.id);
    
    if (!oldPermission) {
      return APIResponse.notFound(res, 'Permission not found');
    }

    const permission = await Permission.findByIdAndUpdate(
      req.params.id,
      { displayName, description, category, isActive },
      { new: true, runValidators: true }
    );

    // Log changes
    const changes = {};
    if (displayName !== oldPermission.displayName) changes.displayName = { from: oldPermission.displayName, to: displayName };
    if (description !== oldPermission.description) changes.description = { from: oldPermission.description, to: description };
    if (category !== oldPermission.category) changes.category = { from: oldPermission.category, to: category };
    if (isActive !== oldPermission.isActive) changes.isActive = { from: oldPermission.isActive, to: isActive };

    await createAuditLog(
      req.user._id,
      'permission_update',
      'system',
      { 
        updated_permission: permission._id,
        changes
      },
      req,
      'success',
      'medium'
    );

    APIResponse.updated(res, { permission }, 'Permission updated successfully');

  } catch (error) {
    next(error);
  }
};

// Delete permission
exports.deletePermission = async (req, res, next) => {
  try {
    const permission = await Permission.findByIdAndDelete(req.params.id);
    
    if (!permission) {
      return APIResponse.notFound(res, 'Permission not found');
    }

    // Log deletion
    await createAuditLog(
      req.user._id,
      'permission_delete',
      'system',
      { 
        deleted_permission: permission._id,
        name: permission.name,
        resource: permission.resource,
        action: permission.action
      },
      req,
      'success',
      'high'
    );

    APIResponse.deleted(res, 'Permission deleted successfully');

  } catch (error) {
    next(error);
  }
};

// Get permission categories
exports.getPermissionCategories = async (req, res, next) => {
  try {
    const categories = await Permission.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);

    APIResponse.success(res, { categories }, 'Permission categories retrieved successfully');

  } catch (error) {
    next(error);
  }
};