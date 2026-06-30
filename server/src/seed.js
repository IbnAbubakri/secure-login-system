import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { loadJSON, saveJSON } from './utils/fileStore.js';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import logger from './utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const USERS_PATH = resolve(__dirname, '../data/users.json');
const SALT_ROUNDS = 12;

const DEMO_EMAIL = 'demo@vault.dev';
const DEMO_PASSWORD = 'VaultXy7!kqmn92';

export default async function seed() {
  const users = loadJSON(USERS_PATH, []);
  if (users.some((u) => u.email === DEMO_EMAIL)) return;

  const hashedPassword = await bcrypt.hash(DEMO_PASSWORD, SALT_ROUNDS);
  const user = {
    id: uuidv4(),
    email: DEMO_EMAIL,
    password: hashedPassword,
    role: 'user',
    createdAt: new Date().toISOString(),
    emailVerified: true,
    emailVerificationToken: null,
    emailVerificationExpires: null,
    mfaSecret: null,
    mfaEnabled: false,
    failedLoginAttempts: 0,
    lockedUntil: null,
    lastLogin: null,
    passwordHistory: [],
    passwordChangedAt: new Date().toISOString(),
  };
  users.push(user);
  saveJSON(USERS_PATH, users);
  logger.info({ email: DEMO_EMAIL }, 'Seeded demo user');
}
