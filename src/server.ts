import express from 'express';
import https from 'node:https';
import fs from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import attestRoutes from './routes/attest';
import dotenv from 'dotenv';

// Load variables from .env into process.env
dotenv.config()

// Reconstruct __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 3000;

// SSL certificate and key paths
const keyPath = join(__dirname, 'certs', process.env.HTTPS_PRIVATE_KEY!);
const certPath = join(__dirname, 'certs', process.env.HTTPS_CERTIFICATE!);

console.log(`🔐 keyPath: ${keyPath}`);
console.log(`🔐 certPath: ${certPath}`);

const sslOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

app.use(express.json());
app.use('/attest', attestRoutes);

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`🚀 App Attest server running at https://localhost:${PORT}`);
});