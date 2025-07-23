require('dotenv').config();

module.exports = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 5001,
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/admin-panel-dashboard'
  },
  jwt: {
    secret: process.env.JWT_SECRET || (() => {
    throw new Error('JWT_SECRET environment variable is required');
  })(),
    expiresIn: process.env.JWT_EXPIRE || '7d'
  },
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12
  }
};