const app = require('./src/app');
const config = require('./src/config');

const PORT = config.port || 5001;

const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} in ${config.nodeEnv} mode`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('💥 Process terminated!');
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received. Exiting gracefully...');
  server.close(() => process.exit(0));
});

process.on('unhandledRejection', (err) => {
  console.log('💥 UNHANDLED REJECTION! Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});