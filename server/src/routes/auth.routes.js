import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import {
  handleLogin, handleRegister, handleLogout, handleRefresh,
  handleMe, handleVerifyEmail, handleForgotPassword,
  handleResetPassword, handleGenerateMFA, handleEnableMFA,
  handleDisableMFA, handleBackupCodes, handleSessions,
  handleDeleteSession, handleLogoutAll, handlePasswordPolicy,
} from '../controllers/auth.controller.js';
import { authenticate } from '../middleware/auth.middleware.js';
import { validateLogin, validateRegister, validatePasswordReset } from '../middleware/validate.middleware.js';
import { csrfToken, validateCsrf } from '../middleware/csrf.middleware.js';

const router = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait before trying again.' },
});

const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 3,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.body?.email || req.ip,
  message: { error: 'Too many requests. Please wait before trying again.' },
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.body?.token || req.ip,
  message: { error: 'Too many reset attempts. Please wait before trying again.' },
});

const mfaGenerateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many MFA requests. Please wait before trying again.' },
});

const mfaVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many MFA attempts. Please wait before trying again.' },
});

router.get('/csrf-token', csrfToken);

router.get('/password-policy', handlePasswordPolicy);

router.post('/register', validateCsrf, validateRegister, handleRegister);

router.post('/login', loginLimiter, validateCsrf, validateLogin, handleLogin);

router.post('/logout', authenticate, validateCsrf, handleLogout);

router.post('/refresh', validateCsrf, handleRefresh);

router.get('/me', authenticate, handleMe);

const verifyEmailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many verification attempts.' },
});

router.get('/verify-email', verifyEmailLimiter, handleVerifyEmail);

router.post('/forgot-password', forgotLimiter, validateCsrf, handleForgotPassword);

router.post('/reset-password', resetLimiter, validateCsrf, validatePasswordReset, handleResetPassword);

router.post('/mfa/generate', authenticate, mfaGenerateLimiter, validateCsrf, handleGenerateMFA);

router.post('/mfa/enable', authenticate, mfaVerifyLimiter, validateCsrf, handleEnableMFA);

router.post('/mfa/disable', authenticate, mfaVerifyLimiter, validateCsrf, handleDisableMFA);

router.post('/mfa/backup-codes', authenticate, mfaGenerateLimiter, validateCsrf, handleBackupCodes);

router.get('/sessions', authenticate, handleSessions);

router.delete('/sessions/:sessionId', authenticate, validateCsrf, handleDeleteSession);

router.post('/logout-all', authenticate, validateCsrf, handleLogoutAll);

export default router;
