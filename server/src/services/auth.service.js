import bcrypt from 'bcrypt';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import { logAction, securityAlert } from './audit.service.js';
import { loadJSON, saveJSON } from '../utils/fileStore.js';
import randomToken from '../utils/randomToken.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const USERS_PATH = resolve(__dirname, '../../data/users.json');
const ATTEMPTS_PATH = resolve(__dirname, '../../data/login-attempts.json');
const SALT_ROUNDS = 12;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

const PASSWORD_POLICY = {
  minLength: 12,
  maxLength: 128,
  minUppercase: 1,
  minLowercase: 1,
  minNumbers: 1,
  minSpecialChars: 1,
  historySize: 5,
  expiryDays: 90,
};

function loadUsers() { return loadJSON(USERS_PATH, []); }
function saveUsers(u) { saveJSON(USERS_PATH, u); }
function loadAttempts() { return loadJSON(ATTEMPTS_PATH, {}); }
function saveAttempts(a) { saveJSON(ATTEMPTS_PATH, a); }

export function getPasswordPolicy() {
  return {
    minLength: PASSWORD_POLICY.minLength,
    maxLength: PASSWORD_POLICY.maxLength,
    minUppercase: PASSWORD_POLICY.minUppercase,
    minLowercase: PASSWORD_POLICY.minLowercase,
    minNumbers: PASSWORD_POLICY.minNumbers,
    minSpecialChars: PASSWORD_POLICY.minSpecialChars,
  };
}

export function validatePasswordComplexity(password) {
  const errors = [];
  if (password.length < PASSWORD_POLICY.minLength) {
    errors.push(`Password must be at least ${PASSWORD_POLICY.minLength} characters.`);
  }
  if (password.length > PASSWORD_POLICY.maxLength) {
    errors.push(`Password must not exceed ${PASSWORD_POLICY.maxLength} characters.`);
  }
  const upper = (password.match(/[A-Z]/g) || []).length;
  const lower = (password.match(/[a-z]/g) || []).length;
  const nums = (password.match(/[0-9]/g) || []).length;
  const special = (password.match(/[^A-Za-z0-9]/g) || []).length;
  if (upper < PASSWORD_POLICY.minUppercase) errors.push(`Must include at least ${PASSWORD_POLICY.minUppercase} uppercase letter(s).`);
  if (lower < PASSWORD_POLICY.minLowercase) errors.push(`Must include at least ${PASSWORD_POLICY.minLowercase} lowercase letter(s).`);
  if (nums < PASSWORD_POLICY.minNumbers) errors.push(`Must include at least ${PASSWORD_POLICY.minNumbers} number(s).`);
  if (special < PASSWORD_POLICY.minSpecialChars) errors.push(`Must include at least ${PASSWORD_POLICY.minSpecialChars} special character(s).`);
  return errors;
}

const HIBP_TIMEOUT_MS = 5000;

async function checkHIBP(password) {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'User-Agent': 'Vault-Secure-Login/1.0' },
      signal: AbortSignal.timeout(HIBP_TIMEOUT_MS),
    });
    if (!res.ok) {
      logger.warn({ status: res.status }, 'HIBP API returned non-OK status');
      return null;
    }
    const text = await res.text();
    const found = text.split('\n').some((line) => {
      const [hashSuffix] = line.split(':');
      return hashSuffix === suffix;
    });
    if (found) logger.warn({ hashPrefix: prefix }, 'Password matches known data breach');
    return found;
  } catch (err) {
    logger.warn({ err: err.message }, 'HIBP API unreachable');
    return null;
  }
}

function isEmailVerified(user) {
  return user.emailVerified === true;
}

function getLockoutDuration(attemptCount) {
  const base = LOCKOUT_MINUTES;
  const extraAttempts = attemptCount - MAX_ATTEMPTS;
  return extraAttempts > 0 ? base * Math.pow(2, extraAttempts) : base;
}

function lockoutKey(email, ip) {
  return `${email.toLowerCase()}:${ip || 'unknown'}`;
}

function isAccountLocked(email, ip) {
  const attempts = loadAttempts();
  const key = lockoutKey(email, ip);
  const record = attempts[key];
  if (!record || record.count < MAX_ATTEMPTS) return false;
  if (new Date(record.lockedUntil) > new Date()) return true;
  delete attempts[key];
  saveAttempts(attempts);
  return false;
}

const LOCKOUT_MULTI_IP_THRESHOLD = 3;

function recordFailedAttempt(email, ip, userAgent) {
  const attempts = loadAttempts();
  const emailKey = email.toLowerCase();
  const ipKey = lockoutKey(email, ip);
  const now = new Date();
  if (!attempts[ipKey] || new Date(attempts[ipKey].lockedUntil) < now) {
    attempts[ipKey] = { count: 0, lastAttempt: now.toISOString(), lockedUntil: null, ips: [] };
  }
  if (!attempts[emailKey] || new Date(attempts[emailKey].lockedUntil) < now) {
    attempts[emailKey] = { count: 0, lastAttempt: now.toISOString(), lockedUntil: null, ips: [] };
  }
  attempts[ipKey].count += 1;
  attempts[emailKey].count += 1;
  attempts[ipKey].lastAttempt = now.toISOString();
  attempts[emailKey].lastAttempt = now.toISOString();
  if (ip && !attempts[ipKey].ips.includes(ip)) {
    attempts[ipKey].ips.push(ip);
  }
  if (ip && !attempts[emailKey].ips.includes(ip)) {
    attempts[emailKey].ips.push(ip);
    if (attempts[emailKey].ips.length >= LOCKOUT_MULTI_IP_THRESHOLD) {
      securityAlert({
        type: 'MULTI_IP_FAILED_LOGINS',
        email: emailKey,
        details: `Failed logins from ${attempts[emailKey].ips.length} different IPs: ${attempts[emailKey].ips.join(', ')}`,
        ip,
      });
    }
  }
  logger.warn({ email: emailKey, attempts: attempts[ipKey].count, ip }, 'Failed login attempt');
  if (attempts[ipKey].count >= MAX_ATTEMPTS) {
    const lockoutMin = getLockoutDuration(attempts[ipKey].count);
    attempts[ipKey].lockedUntil = new Date(now.getTime() + lockoutMin * 60 * 1000).toISOString();
    logger.warn({ email: emailKey, attempts: attempts[ipKey].count, lockoutMin, ip }, 'Account locked due to failed attempts');
    securityAlert({
      type: 'ACCOUNT_LOCKED',
      email: emailKey,
      details: `Account locked for ${lockoutMin} minutes after ${attempts[ipKey].count} failed attempts from ${ip}`,
      ip,
    });
  }
  saveAttempts(attempts);
}

function clearFailedAttempts(email, ip) {
  const attempts = loadAttempts();
  delete attempts[lockoutKey(email, ip)];
  saveAttempts(attempts);
}

export async function register({ email, password, ip, userAgent }) {
  const users = loadUsers();
  if (users.some((u) => u.email === email.toLowerCase())) {
    throw new AppError('Email already registered.', 409);
  }
  const complexityErrors = validatePasswordComplexity(password);
  if (complexityErrors.length) {
    throw new AppError(complexityErrors.join(' '), 400);
  }
  const pwned = await checkHIBP(password);
  if (pwned === true) {
    logAction({ userId: null, action: 'REGISTER_BREACHED_PASSWORD', details: { email: email.toLowerCase() }, ip, userAgent, severity: 'high' });
    throw new AppError('Password has been exposed in a data breach. Choose a different one.', 400);
  }
  if (pwned === null) {
    throw new AppError('Cannot verify password security. Please try again later.', 503);
  }
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  const user = {
    id: uuidv4(),
    email: email.toLowerCase(),
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
  saveUsers(users);
  logAction({ userId: user.id, action: 'REGISTER', details: { email: user.email }, ip, userAgent });
  logger.info({ userId: user.id }, 'User registered');
  return { id: user.id, email: user.email, role: user.role, emailVerified: true };
}

export async function authenticate(email, password, totpCode, ip, userAgent) {
  const users = loadUsers();
  const user = users.find((u) => u.email === email.toLowerCase());
  if (!user) {
    await new Promise((r) => setTimeout(r, 500));
    throw new AppError('Invalid email or password.', 401);
  }
  if (isAccountLocked(email, ip)) {
    logAction({ userId: user.id, action: 'LOGIN_LOCKED', details: { email: email.toLowerCase() }, ip, userAgent, severity: 'high' });
    throw new AppError('Account temporarily locked. Try again later.', 423);
  }
  if (!isEmailVerified(user)) {
    throw new AppError('Please verify your email before signing in.', 403);
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    recordFailedAttempt(email, ip, userAgent);
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
        logAction({ userId: user.id, action: 'MFA_FAILED', details: { email: email.toLowerCase() }, ip, userAgent, severity: 'high' });
        throw new AppError('Invalid two-factor code.', 401);
      }
      user.mfaBackupCodes[idx].used = true;
      logAction({ userId: user.id, action: 'MFA_BACKUP_CODE_USED', details: {}, ip, userAgent, severity: 'high' });
    }
  }
  clearFailedAttempts(email, ip);
  user.lastLogin = new Date().toISOString();
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  saveUsers(users);
  logAction({ userId: user.id, action: 'LOGIN', details: { email: user.email }, ip, userAgent });
  logger.info({ userId: user.id }, 'User authenticated');
  return { id: user.id, email: user.email, role: user.role };
}

export async function verifyEmail(token, ip, userAgent) {
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
  logAction({ userId: user.id, action: 'EMAIL_VERIFIED', details: { email: user.email }, ip, userAgent });
  logger.info({ userId: user.id }, 'Email verified');
  return { id: user.id, email: user.email };
}

export async function forgotPassword(email, ip, userAgent) {
  const users = loadUsers();
  const user = users.find((u) => u.email === email.toLowerCase());
  if (!user) return { message: 'If that email exists, a reset link has been sent.' };
  const resetToken = randomToken(32);
  user.resetToken = resetToken;
  user.resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  saveUsers(users);
  logAction({ userId: user.id, action: 'PASSWORD_RESET_REQUESTED', details: { email: user.email }, ip, userAgent, severity: 'high' });
  stubEmail(email, 'Password Reset', `Reset: /reset-password?token=${resetToken}`);
  logger.info({ userId: user.id }, 'Password reset requested');
  return { message: 'If that email exists, a reset link has been sent.' };
}

export async function resetPassword(token, newPassword, ip, userAgent) {
  const complexityErrors = validatePasswordComplexity(newPassword);
  if (complexityErrors.length) {
    throw new AppError(complexityErrors.join(' '), 400);
  }
  const users = loadUsers();
  const user = users.find((u) => u.resetToken === token);
  if (!user || new Date(user.resetTokenExpires) < new Date()) {
    throw new AppError('Invalid or expired reset token.', 400);
  }
  const pwned = await checkHIBP(newPassword);
  if (pwned === true) {
    logAction({ userId: user.id, action: 'RESET_BREACHED_PASSWORD', details: {}, ip, userAgent, severity: 'high' });
    throw new AppError('Password has been exposed in a data breach. Choose a different one.', 400);
  }
  if (pwned === null) {
    throw new AppError('Cannot verify password security. Please try again later.', 503);
  }
  if (!user.passwordHistory) user.passwordHistory = [];
  for (const oldHash of user.passwordHistory) {
    if (await bcrypt.compare(newPassword, oldHash)) {
      throw new AppError('Cannot reuse a recent password.', 400);
    }
  }
  user.passwordHistory.push(user.password);
  if (user.passwordHistory.length > PASSWORD_POLICY.historySize) {
    user.passwordHistory.shift();
  }
  user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
  user.passwordChangedAt = new Date().toISOString();
  user.resetToken = null;
  user.resetTokenExpires = null;
  user.emailVerified = true;
  saveUsers(users);
  logAction({ userId: user.id, action: 'PASSWORD_RESET_COMPLETED', details: {}, ip, userAgent, severity: 'high' });
  logger.info({ userId: user.id }, 'Password reset completed');
  return { userId: user.id, message: 'Password updated.' };
}

export async function generateMFASecret(userId, ip, userAgent) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) throw new AppError('User not found.', 404);
  const { authenticator } = await import('otplib');
  const secret = authenticator.generateSecret();
  const uri = authenticator.keyuri(user.email, 'Vault', secret);
  user.mfaSecret = secret;
  saveUsers(users);
  logAction({ userId, action: 'MFA_SECRET_GENERATED', details: {}, ip, userAgent, severity: 'high' });
  return { secret, uri };
}

function generateBackupCodes() {
  const codes = [];
  const hashes = [];
  for (let i = 0; i < 10; i++) {
    const code = randomToken(4).toUpperCase();
    codes.push(code);
    hashes.push({ hash: crypto.createHash('sha256').update(code).digest('hex'), used: false });
  }
  return { codes, hashes };
}

export async function enableMFA(userId, code, ip, userAgent) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user || !user.mfaSecret) throw new AppError('MFA not initialized.', 400);
  const { authenticator } = await import('otplib');
  if (!authenticator.check(code, user.mfaSecret)) {
    logAction({ userId, action: 'MFA_ENABLE_FAILED', details: {}, ip, userAgent, severity: 'high' });
    throw new AppError('Invalid code.', 401);
  }
  const { codes, hashes } = generateBackupCodes();
  user.mfaEnabled = true;
  user.mfaBackupCodes = hashes;
  saveUsers(users);
  logAction({ userId, action: 'MFA_ENABLED', details: {}, ip, userAgent, severity: 'high' });
  logger.info({ userId: user.id }, 'MFA enabled');
  return { mfaEnabled: true, backupCodes: codes };
}

export async function disableMFA(userId, ip, userAgent) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) throw new AppError('User not found.', 404);
  user.mfaSecret = null;
  user.mfaEnabled = false;
  saveUsers(users);
  logAction({ userId, action: 'MFA_DISABLED', details: {}, ip, userAgent, severity: 'high' });
  securityAlert({
    type: 'MFA_DISABLED',
    userId,
    details: 'User disabled MFA on their account',
    ip,
  });
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

export async function regenerateBackupCodes(userId, ip, userAgent) {
  const users = loadUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) throw new AppError('User not found.', 404);
  const { codes, hashes } = generateBackupCodes();
  user.mfaBackupCodes = hashes;
  saveUsers(users);
  logAction({ userId, action: 'MFA_BACKUP_CODES_REGENERATED', details: {}, ip, userAgent, severity: 'high' });
  logger.info({ userId: user.id }, 'MFA backup codes regenerated');
  return { backupCodes: codes };
}

function stubEmail(to, subject, body) {
  logger.info({ emailTo: to, subject }, `[EMAIL STUB] ${body}`);
}
