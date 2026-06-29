import bcrypt from 'bcrypt';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const USERS_PATH = resolve(__dirname, '../../data/users.json');
const ATTEMPTS_PATH = resolve(__dirname, '../../data/login-attempts.json');
const SALT_ROUNDS = 12;
const MIN_PASSWORD = 12;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

function loadJSON(path, fallback) {
  if (!existsSync(path)) return fallback;
  try { return JSON.parse(readFileSync(path, 'utf-8')); }
  catch { return fallback; }
}

function saveJSON(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8');
}

function loadUsers() { return loadJSON(USERS_PATH, []); }
function saveUsers(u) { saveJSON(USERS_PATH, u); }
function loadAttempts() { return loadJSON(ATTEMPTS_PATH, {}); }
function saveAttempts(a) { saveJSON(ATTEMPTS_PATH, a); }

export function getMinPasswordLength() { return MIN_PASSWORD; }

async function checkHIBP(password) {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (res.ok) {
      const text = await res.text();
      return text.split('\n').some((line) => line.startsWith(suffix));
    }
  } catch {}
  return false;
}

function isEmailVerified(user) {
  return user.emailVerified === true;
}

function getLockoutDuration(attemptCount) {
  const base = LOCKOUT_MINUTES;
  const extraAttempts = attemptCount - MAX_ATTEMPTS;
  return extraAttempts > 0 ? base * Math.pow(2, extraAttempts) : base;
}

function isAccountLocked(email) {
  const attempts = loadAttempts();
  const record = attempts[email.toLowerCase()];
  if (!record || record.count < MAX_ATTEMPTS) return false;
  if (new Date(record.lockedUntil) > new Date()) return true;
  delete attempts[email.toLowerCase()];
  saveAttempts(attempts);
  return false;
}

function recordFailedAttempt(email) {
  const attempts = loadAttempts();
  const key = email.toLowerCase();
  const now = new Date();
  if (!attempts[key] || new Date(attempts[key].lockedUntil) < now) {
    attempts[key] = { count: 0, lastAttempt: now.toISOString(), lockedUntil: null };
  }
  attempts[key].count += 1;
  attempts[key].lastAttempt = now.toISOString();
  logger.warn({ email: key, attempts: attempts[key].count }, 'Failed login attempt');
  if (attempts[key].count >= MAX_ATTEMPTS) {
    const lockoutMin = getLockoutDuration(attempts[key].count);
    attempts[key].lockedUntil = new Date(now.getTime() + lockoutMin * 60 * 1000).toISOString();
    logger.warn({ email: key, attempts: attempts[key].count, lockoutMin }, 'Account locked due to failed attempts');
  }
  saveAttempts(attempts);
}

function clearFailedAttempts(email) {
  const attempts = loadAttempts();
  delete attempts[email.toLowerCase()];
  saveAttempts(attempts);
}

export async function register({ email, password }) {
  const users = loadUsers();
  if (users.some((u) => u.email === email.toLowerCase())) {
    throw new AppError('Email already registered.', 409);
  }
  if (password.length < MIN_PASSWORD) {
    throw new AppError(`Password must be at least ${MIN_PASSWORD} characters.`, 400);
  }
  const pwned = await checkHIBP(password);
  if (pwned) {
    throw new AppError('Password has been exposed in a data breach. Choose a different one.', 400);
  }
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const user = {
    id: uuidv4(),
    email: email.toLowerCase(),
    password: hashedPassword,
    role: 'user',
    createdAt: new Date().toISOString(),
    emailVerified: false,
    emailVerificationToken: verifyToken,
    emailVerificationExpires: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    mfaSecret: null,
    mfaEnabled: false,
    failedLoginAttempts: 0,
    lockedUntil: null,
    lastLogin: null,
  };
  users.push(user);
  saveUsers(users);
  logger.info({ userId: user.id }, 'User registered');
  stubEmail(email, 'Verify your email', `Verify: /api/auth/verify-email?token=${verifyToken}`);
  return { id: user.id, email: user.email, role: user.role, emailVerified: false };
}

export async function authenticate(email, password, totpCode) {
  const users = loadUsers();
  const user = users.find((u) => u.email === email.toLowerCase());
  if (!user) {
    await new Promise((r) => setTimeout(r, 500));
    throw new AppError('Invalid email or password.', 401);
  }
  if (isAccountLocked(email)) {
    throw new AppError('Account temporarily locked. Try again later.', 423);
  }
  if (!isEmailVerified(user)) {
    throw new AppError('Please verify your email before signing in.', 403);
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    recordFailedAttempt(email);
    throw new AppError('Invalid email or password.', 401);
  }
  if (user.mfaEnabled) {
    if (!totpCode) {
      return { mfaRequired: true, tempEmail: user.email };
    }
    const { authenticator } = await import('otplib');
    const isValid = authenticator.check(totpCode, user.mfaSecret);
    if (!isValid) {
      const codes = user.mfaBackupCodes || [];
      const codeHash = crypto.createHash('sha256').update(totpCode).digest('hex');
      const idx = codes.findIndex((bc) => bc.hash === codeHash && !bc.used);
      if (idx === -1) {
        throw new AppError('Invalid two-factor code.', 401);
      }
      user.mfaBackupCodes[idx].used = true;
      logger.info({ userId: user.id }, 'MFA backup code used');
    }
  }
  clearFailedAttempts(email);
  user.lastLogin = new Date().toISOString();
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  saveUsers(users);
  logger.info({ userId: user.id }, 'User authenticated');
  return { id: user.id, email: user.email, role: user.role };
}

export async function verifyEmail(token) {
  const users = loadUsers();
  const user = users.find((u) => u.emailVerificationToken === token);
  if (!user) throw new AppError('Invalid verification token.', 400);
  if (new Date(user.emailVerificationExpires) < new Date()) {
    throw new AppError('Verification token expired.', 400);
  }
  user.emailVerified = true;
  user.emailVerificationToken = null;
  user.emailVerificationExpires = null;
  saveUsers(users);
  logger.info({ userId: user.id }, 'Email verified');
  return { id: user.id, email: user.email };
}

export async function forgotPassword(email) {
  const users = loadUsers();
  const user = users.find((u) => u.email === email.toLowerCase());
  if (!user) return { message: 'If that email exists, a reset link has been sent.' };
  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetToken = resetToken;
  user.resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  saveUsers(users);
  stubEmail(email, 'Password Reset', `Reset: /reset-password?token=${resetToken}`);
  logger.info({ userId: user.id }, 'Password reset requested');
  return { message: 'If that email exists, a reset link has been sent.' };
}

export async function resetPassword(token, newPassword) {
  if (newPassword.length < MIN_PASSWORD) {
    throw new AppError(`Password must be at least ${MIN_PASSWORD} characters.`, 400);
  }
  const users = loadUsers();
  const user = users.find((u) => u.resetToken === token);
  if (!user || new Date(user.resetTokenExpires) < new Date()) {
    throw new AppError('Invalid or expired reset token.', 400);
  }
  const pwned = await checkHIBP(newPassword);
  if (pwned) {
    throw new AppError('Password has been exposed in a data breach. Choose a different one.', 400);
  }
  user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
  user.resetToken = null;
  user.resetTokenExpires = null;
  user.emailVerified = true;
  saveUsers(users);
  logger.info({ userId: user.id }, 'Password reset completed');
  return { userId: user.id, message: 'Password updated.' };
}

export async function generateMFASecret(userId) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) throw new AppError('User not found.', 404);
  const { authenticator } = await import('otplib');
  const secret = authenticator.generateSecret();
  const uri = authenticator.keyuri(user.email, 'Vault', secret);
  user.mfaSecret = secret;
  saveUsers(users);
  return { secret, uri };
}

function generateBackupCodes() {
  const codes = [];
  const hashes = [];
  for (let i = 0; i < 10; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(code);
    hashes.push({ hash: crypto.createHash('sha256').update(code).digest('hex'), used: false });
  }
  return { codes, hashes };
}

export async function enableMFA(userId, code) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user || !user.mfaSecret) throw new AppError('MFA not initialized.', 400);
  const { authenticator } = await import('otplib');
  if (!authenticator.check(code, user.mfaSecret)) {
    throw new AppError('Invalid code.', 401);
  }
  const { codes, hashes } = generateBackupCodes();
  user.mfaEnabled = true;
  user.mfaBackupCodes = hashes;
  saveUsers(users);
  logger.info({ userId: user.id }, 'MFA enabled');
  return { mfaEnabled: true, backupCodes: codes };
}

export async function disableMFA(userId) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) throw new AppError('User not found.', 404);
  user.mfaSecret = null;
  user.mfaEnabled = false;
  saveUsers(users);
  logger.info({ userId: user.id }, 'MFA disabled');
  return { mfaEnabled: false };
}

export function getUserById(id) {
  const users = loadUsers();
  const user = users.find((u) => u.id === id);
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    emailVerified: user.emailVerified,
    mfaEnabled: user.mfaEnabled,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
  };
}

export async function regenerateBackupCodes(userId) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) throw new AppError('User not found.', 404);
  const { codes, hashes } = generateBackupCodes();
  user.mfaBackupCodes = hashes;
  saveUsers(users);
  logger.info({ userId: user.id }, 'MFA backup codes regenerated');
  return { backupCodes: codes };
}

function stubEmail(to, subject, body) {
  logger.info({ emailTo: to, subject }, `[EMAIL STUB] ${body}`);
}
