const mongoose = require('mongoose');
const config = require('./index');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(config.mongodb.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log(`📊 MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
    process.exit(1);
  }
};

module.exports = connectDB;