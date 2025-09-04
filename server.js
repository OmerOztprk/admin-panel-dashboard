require('dotenv').config();
const app = require('./src/app');
const config = require('./src/config');

const PORT = config.port;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
