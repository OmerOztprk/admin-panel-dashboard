const APIResponse = require('../utils/response');

const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    url: req.originalUrl
  });

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = req.t('errors.notFound');
    return APIResponse.notFound(res, message);
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`;
    return APIResponse.error(res, message, 400);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(val => val.message);
    return APIResponse.validationError(res, errors, req.t('errors.validation'));
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return APIResponse.unauthorized(res, req.t('errors.unauthorized'));
  }

  if (err.name === 'TokenExpiredError') {
    return APIResponse.unauthorized(res, 'Token expired');
  }

  // Default error
  return APIResponse.error(res,
    error.message || req.t('errors.serverError'),
    error.statusCode || 500
  );
};

module.exports = errorHandler;