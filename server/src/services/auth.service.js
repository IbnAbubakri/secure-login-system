// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import { logAction, securityAlert } from './audit.service.js';
import { query } from '../db/index.js';
import randomToken from '../utils/randomToken.js';
import { sendEmail } from './email.service.js';

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

async function isAccountLocked(email, ip) {
  const { rows } = await query(
    'SELECT count FROM login_attempts WHERE key = $1',
    [lockoutKey(email, ip)],
  );
  const record = rows[0];
  if (!record || record.count < MAX_ATTEMPTS) return false;
  if (record.locked_until && new Date(record.locked_until) > new Date()) return true;
  await query('DELETE FROM login_attempts WHERE key = $1', [lockoutKey(email, ip)]);
  return false;
}

const LOCKOUT_MULTI_IP_THRESHOLD = 3;

async function recordFailedAttempt(email, ip, userAgent) {
  const emailKey = email.toLowerCase();
  const ipKey = lockoutKey(email, ip);
  const now = new Date();

  async function bump(key) {
    const { rows } = await query('SELECT count FROM login_attempts WHERE key = $1', [key]);
    const isExpired = rows[0] && rows[0].locked_until && new Date(rows[0].locked_until) < now;
    if (!rows[0] || isExpired) {
      await query(
        'INSERT INTO login_attempts (key, count, last_attempt, locked_until, ips) VALUES ($1, 1, now(), NULL, $2::text[])',
        [key, ip ? [ip] : []],
      );
      return 1;
    }
    const count = rows[0].count + 1;
    await query('UPDATE login_attempts SET count = $1, last_attempt = now() WHERE key = $2', [count, key]);
    return count;
  }

  const ipCount = await bump(ipKey);
  const emailCount = await bump(emailKey);

  if (ip && emailCount >= LOCKOUT_MULTI_IP_THRESHOLD) {
    const { rows } = await query('SELECT ips FROM login_attempts WHERE key = $1', [emailKey]);
    if (rows[0] && !rows[0].ips.includes(ip)) {
      await query('UPDATE login_attempts SET ips = ips || $1::text[] WHERE key = $2', [[ip], emailKey]);
      const { rows: ipRows } = await query('SELECT ips FROM login_attempts WHERE key = $1', [emailKey]);
      if (ipRows[0].ips.length >= LOCKOUT_MULTI_IP_THRESHOLD) {
        securityAlert({
          type: 'MULTI_IP_FAILED_LOGINS',
          email: emailKey,
          details: `Failed logins from ${ipRows[0].ips.length} different IPs: ${ipRows[0].ips.join(', ')}`,
          ip,
        });
      }
    }
  } else if (ip) {
    await query('UPDATE login_attempts SET ips = CASE WHEN NOT (ips @> $2::text[]) THEN ips || $2::text[] ELSE ips END WHERE key = $1', [emailKey, [ip]]);
  }

  logger.warn({ email: emailKey, attempts: ipCount, ip, userAgent }, 'Failed login attempt');

  if (ipCount >= MAX_ATTEMPTS) {
    const minutes = getLockoutDuration(ipCount);
    const lockedUntil = new Date(now.getTime() + minutes * 60 * 1000).toISOString();
    await query('UPDATE login_attempts SET locked_until = $1 WHERE key = $2', [lockedUntil, ipKey]);
    logger.warn({ email: emailKey, attempts: ipCount, lockoutMin: minutes, ip }, 'Account locked due to failed attempts');
    securityAlert({
      type: 'ACCOUNT_LOCKED',
      email: emailKey,
      details: `Account locked for ${minutes} minutes after ${ipCount} failed attempts from ${ip}`,
      ip,
    });
  }
}

async function clearFailedAttempts(email, ip) {
  await query('DELETE FROM login_attempts WHERE key = $1', [lockoutKey(email, ip)]);
  await query('DELETE FROM login_attempts WHERE key = $1', [email.toLowerCase()]);
}

function mapUserRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    password: row.password,
    role: row.role,
    createdAt: row.created_at,
    emailVerified: row.email_verified,
    emailVerificationToken: row.email_verification_token,
    emailVerificationExpires: row.email_verification_expires,
    mfaSecret: row.mfa_secret,
    mfaEnabled: row.mfa_enabled,
    lastLogin: row.last_login,
    passwordHistory: row.password_history || [],
    passwordChangedAt: row.password_changed_at,
    resetToken: row.reset_token,
    resetTokenExpires: row.reset_token_expires,
    mfaBackupCodes: row.mfa_backup_codes || [],
  };
}

async function findUserByEmail(email) {
  const { rows } = await query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
  return mapUserRow(rows[0]);
}

async function findUserById(id) {
  const { rows } = await query('SELECT * FROM users WHERE id = $1', [id]);
  return mapUserRow(rows[0]);
}

async function findUserByVerificationToken(token) {
  const { rows } = await query('SELECT * FROM users WHERE email_verification_token = $1', [token]);
  return mapUserRow(rows[0]);
}

async function findUserByResetToken(token) {
  const { rows } = await query('SELECT * FROM users WHERE reset_token = $1', [token]);
  return mapUserRow(rows[0]);
}

export async function register({ email, password, ip, userAgent }) {
  const existing = await findUserByEmail(email);
  if (existing) {
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
  const id = uuidv4();
  const verificationToken = randomToken(32);
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = new Date().toISOString();
  await query(
    `INSERT INTO users (id, email, password, role, created_at, email_verified, email_verification_token, email_verification_expires, mfa_secret, mfa_enabled, password_history, password_changed_at)
     VALUES ($1, $2, $3, 'user', $4, false, $5, $6, NULL, false, '[]'::jsonb, $4)`,
    [id, email.toLowerCase(), hashedPassword, created, verificationToken, verificationExpires],
  );
  const user = { id, email: email.toLowerCase(), role: 'user' };
  logAction({ userId: id, action: 'REGISTER', details: { email: user.email }, ip, userAgent });
  logger.info({ userId: id }, 'User registered');
  await sendEmailSafe(user.email, 'Verify your Vault account', `Verify: ${appVerificationUrl(verificationToken)}`);
  return {
    id,
    email: user.email,
    role: 'user',
    emailVerified: false,
  };
}

function appVerificationUrl(token) {
  const origin = process.env.PUBLIC_ORIGIN || `http://localhost:${process.env.PORT || 4000}`;
  return `${origin}/api/auth/verify-email?token=${encodeURIComponent(token)}`;
}

function appPasswordResetUrl(token) {
  const origin = process.env.PUBLIC_ORIGIN || `http://localhost:${process.env.PORT || 4000}`;
  return `${origin}/reset-password?token=${encodeURIComponent(token)}`;
}

const DUMMY_HASH = '$2b$12$jKMF9kIud3EFjOtXpQ9pu.urQALrBGxNGf7majjophjGStsfGZ41m';

async function verifyTotp(secret, token) {
  if (!secret || typeof token !== 'string' || !/^[0-9]{6}$/.test(token)) return false;
  try {
    const { verify } = await import('otplib');
    const result = await verify({ secret, token });
    return result?.valid === true;
  } catch {
    return false;
  }
}

export async function authenticate(email, password, totpCode, ip, userAgent) {
  const user = await findUserByEmail(email);
  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH);
    logger.warn({ email: email.toLowerCase(), ip }, 'Login attempt for unknown email');
    throw new AppError('Invalid email or password.', 401);
  }
  if (await isAccountLocked(email, ip)) {
    logAction({ userId: user.id, action: 'LOGIN_LOCKED', details: { email: email.toLowerCase() }, ip, userAgent, severity: 'high' });
    throw new AppError('Account temporarily locked. Try again later.', 423);
  }
  if (!isEmailVerified(user)) {
    throw new AppError('Please verify your email before signing in.', 403);
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    await recordFailedAttempt(email, ip, userAgent);
    throw new AppError('Invalid email or password.', 401);
  }
  if (user.mfaEnabled) {
    if (!totpCode) {
      return { mfaRequired: true, tempEmail: user.email };
    }
    const isCodeValid = await verifyTotp(user.mfaSecret, totpCode);
    if (!isCodeValid) {
      const codes = user.mfaBackupCodes || [];
      const codeHash = crypto.createHash('sha256').update(totpCode).digest('hex');
      const idx = codes.findIndex((bc) => bc.hash === codeHash && !bc.used);
      if (idx === -1) {
        logAction({ userId: user.id, action: 'MFA_FAILED', details: { email: email.toLowerCase() }, ip, userAgent, severity: 'high' });
        throw new AppError('Invalid two-factor code.', 401);
      }
      codes[idx].used = true;
      await query('UPDATE users SET mfa_backup_codes = $1 WHERE id = $2', [JSON.stringify(codes), user.id]);
      logAction({ userId: user.id, action: 'MFA_BACKUP_CODE_USED', details: {}, ip, userAgent, severity: 'high' });
    }
  }
  await clearFailedAttempts(email, ip);
  await query('UPDATE users SET last_login = now() WHERE id = $1', [user.id]);
  logAction({ userId: user.id, action: 'LOGIN', details: { email: user.email }, ip, userAgent });
  logger.info({ userId: user.id }, 'User authenticated');
  return { id: user.id, email: user.email, role: user.role };
}

export async function verifyEmail(token, ip, userAgent) {
  const user = await findUserByVerificationToken(token);
  if (!user) throw new AppError('Invalid verification token.', 400);
  if (new Date(user.emailVerificationExpires) < new Date()) {
    throw new AppError('Verification token expired.', 400);
  }
  await query(
    'UPDATE users SET email_verified = true, email_verification_token = NULL, email_verification_expires = NULL WHERE id = $1',
    [user.id],
  );
  logAction({ userId: user.id, action: 'EMAIL_VERIFIED', details: { email: user.email }, ip, userAgent });
  logger.info({ userId: user.id }, 'Email verified');
  return { id: user.id, email: user.email };
}

export async function forgotPassword(email, ip, userAgent) {
  const user = await findUserByEmail(email);
  if (!user) return { message: 'If that email exists, a reset link has been sent.' };
  const resetToken = randomToken(32);
  const resetExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  await query('UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3', [resetToken, resetExpires, user.id]);
  logAction({ userId: user.id, action: 'PASSWORD_RESET_REQUESTED', details: { email: user.email }, ip, userAgent, severity: 'high' });
  await sendEmailSafe(email, 'Password Reset', `Reset: ${appPasswordResetUrl(resetToken)}`);
  logger.info({ userId: user.id }, 'Password reset requested');
  return { message: 'If that email exists, a reset link has been sent.' };
}

export async function resetPassword(token, newPassword, ip, userAgent) {
  const complexityErrors = validatePasswordComplexity(newPassword);
  if (complexityErrors.length) {
    throw new AppError(complexityErrors.join(' '), 400);
  }
  const user = await findUserByResetToken(token);
  if (!user || (user.resetTokenExpires && new Date(user.resetTokenExpires) < new Date())) {
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
  const history = user.passwordHistory || [];
  for (const oldHash of history) {
    if (await bcrypt.compare(newPassword, oldHash)) {
      throw new AppError('Cannot reuse a recent password.', 400);
    }
  }
  history.push(user.password);
  if (history.length > PASSWORD_POLICY.historySize) {
    history.shift();
  }
  const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  await query(
    `UPDATE users SET password = $1, password_changed_at = now(), password_history = $2::jsonb,
       reset_token = NULL, reset_token_expires = NULL, email_verified = true
     WHERE id = $3`,
    [newHash, JSON.stringify(history), user.id],
  );
  logAction({ userId: user.id, action: 'PASSWORD_RESET_COMPLETED', details: {}, ip, userAgent, severity: 'high' });
  logger.info({ userId: user.id }, 'Password reset completed');
  return { userId: user.id, message: 'Password updated.' };
}

export async function generateMFASecret(userId, ip, userAgent) {
  const user = await findUserById(userId);
  if (!user) throw new AppError('User not found.', 404);
  const { generateSecret, generateURI } = await import('otplib');
  const secret = generateSecret();
  const uri = generateURI({ issuer: 'Vault', label: user.email, secret });
  await query('UPDATE users SET mfa_secret = $1 WHERE id = $2', [secret, userId]);
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
  const user = await findUserById(userId);
  if (!user || !user.mfaSecret) throw new AppError('MFA not initialized.', 400);
  const isCodeValid = await verifyTotp(user.mfaSecret, code);
  if (!isCodeValid) {
    logAction({ userId, action: 'MFA_ENABLE_FAILED', details: {}, ip, userAgent, severity: 'high' });
    throw new AppError('Invalid code.', 401);
  }
  const { codes, hashes } = generateBackupCodes();
  await query(
    'UPDATE users SET mfa_enabled = true, mfa_backup_codes = $1 WHERE id = $2',
    [JSON.stringify(hashes), userId],
  );
  logAction({ userId, action: 'MFA_ENABLED', details: {}, ip, userAgent, severity: 'high' });
  logger.info({ userId: user.id }, 'MFA enabled');
  return { mfaEnabled: true, backupCodes: codes };
}

export async function disableMFA(userId, code, ip, userAgent) {
  const user = await findUserById(userId);
  if (!user) throw new AppError('User not found.', 404);
  if (!user.mfaEnabled || !user.mfaSecret) throw new AppError('MFA is not enabled for this account.', 400);
  const isCodeValid = await verifyTotp(user.mfaSecret, code);
  if (!isCodeValid) {
    logAction({ userId, action: 'MFA_DISABLE_FAILED', details: {}, ip, userAgent, severity: 'high' });
    throw new AppError('Invalid two-factor code.', 401);
  }
  await query('UPDATE users SET mfa_secret = NULL, mfa_enabled = false, mfa_backup_codes = NULL WHERE id = $1', [userId]);
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

export async function getUserById(id) {
  const user = await findUserById(id);
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
  const user = await findUserById(userId);
  if (!user) throw new AppError('User not found.', 404);
  const { codes, hashes } = generateBackupCodes();
  await query('UPDATE users SET mfa_backup_codes = $1 WHERE id = $2', [JSON.stringify(hashes), userId]);
  logAction({ userId, action: 'MFA_BACKUP_CODES_REGENERATED', details: {}, ip, userAgent, severity: 'high' });
  logger.info({ userId: user.id }, 'MFA backup codes regenerated');
  return { backupCodes: codes };
}

async function sendEmailSafe(to, subject, body) {
  try {
    await sendEmail(to, subject, body);
  } catch (err) {
    logger.error({ err: err.message, emailTo: to, subject }, 'Email delivery failed');
  }
}