import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();

// Serve static files from dist directory
app.use(express.static(join(__dirname, 'dist')));

// Handle client-side routing - serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, 'dist', 'index.html'));
});

const port = process.env.PORT || 4173;
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${port}`);
});