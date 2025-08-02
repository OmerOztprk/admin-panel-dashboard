const APIResponse = require('../utils/response');

/**
 * Base Service Class
 * Tüm service'ler için ortak metodları içerir
 */
class BaseService {
  constructor(model) {
    this.model = model;
  }

  // Pagination helper
  getPaginationOptions(query) {
    const page = parseInt(query.page) || 1;
    const limit = parseInt(query.limit) || 10;
    const skip = (page - 1) * limit;
    const sortBy = query.sortBy || 'createdAt';
    const sortOrder = query.sortOrder === 'asc' ? 1 : -1;

    return {
      page,
      limit,
      skip,
      sort: { [sortBy]: sortOrder }
    };
  }

  // Build pagination response
  buildPaginationResponse(data, total, options) {
    const totalPages = Math.ceil(total / options.limit);

    return {
      data,
      pagination: {
        currentPage: options.page,
        totalPages,
        total,
        hasNextPage: options.page < totalPages,
        hasPrevPage: options.page > 1,
        limit: options.limit
      }
    };
  }

  // Generic find with pagination
  async findWithPagination(filter = {}, options = {}) {
    const paginationOptions = this.getPaginationOptions(options);

    const data = await this.model
      .find(filter)
      .sort(paginationOptions.sort)
      .skip(paginationOptions.skip)
      .limit(paginationOptions.limit);

    const total = await this.model.countDocuments(filter);

    return this.buildPaginationResponse(data, total, paginationOptions);
  }

  // Generic find by ID
  async findById(id, populate = null) {
    let query = this.model.findById(id);

    if (populate) {
      if (Array.isArray(populate)) {
        populate.forEach(pop => query = query.populate(pop));
      } else {
        query = query.populate(populate);
      }
    }

    return await query;
  }

  // Generic create
  async create(data) {
    return await this.model.create(data);
  }

  // Generic update
  async update(id, data) {
    return await this.model.findByIdAndUpdate(
      id,
      data,
      { new: true, runValidators: true }
    );
  }

  // Generic delete
  async delete(id) {
    return await this.model.findByIdAndDelete(id);
  }

  // Check if document exists
  async exists(filter) {
    return await this.model.exists(filter);
  }

  // Count documents
  async count(filter = {}) {
    return await this.model.countDocuments(filter);
  }
}

module.exports = BaseService;