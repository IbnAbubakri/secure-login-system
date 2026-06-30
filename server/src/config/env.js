import { config } from 'dotenv';
import randomToken from '../utils/randomToken.js';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

config({ path: resolve(__dirname, '../../.env') });

const env = {
  PORT: parseInt(process.env.PORT, 10) || 4000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_ACCESS_EXPIRES_IN: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  CORS_ORIGIN: process.env.CORS_ORIGIN || 'http://localhost:5173',
  isDev: () => env.NODE_ENV === 'development',
  isProd: () => env.NODE_ENV === 'production',
};

const DEFAULT_SECRET = 'change-this-to-a-long-random-string-in-production';
if (!env.JWT_SECRET || env.JWT_SECRET === DEFAULT_SECRET) {
  env.JWT_SECRET = randomToken(32);
  console.warn('WARNING: JWT_SECRET is weak or default. Auto-generated a random secret for this session.');
}

export default env;
