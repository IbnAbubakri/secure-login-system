import {
  authenticate, register, getUserById, verifyEmail,
  forgotPassword, resetPassword, generateMFASecret,
  enableMFA, disableMFA, regenerateBackupCodes, getMinPasswordLength,
} from '../services/auth.service.js';
import {
  generateAccessToken, generateRefreshToken,
  rotateRefreshToken, revokeRefreshToken,
  revokeAllUserRefreshTokens, getStoredRefreshToken,
  createSession, updateSessionActivity, getSessionsByUserId,
  deleteSession, deleteAllUserSessions,
} from '../services/token.service.js';
import logger from '../utils/logger.js';

function setAuthCookies(res, accessToken, refreshToken) {
  const opts = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  };
  res.cookie('accessToken', accessToken, { ...opts, maxAge: 15 * 60 * 1000 });
  if (refreshToken) {
    res.cookie('refreshToken', refreshToken, {
      ...opts, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/api/auth',
    });
  }
}

function clearAuthCookies(res) {
  res.clearCookie('accessToken', { path: '/' });
  res.clearCookie('refreshToken', { path: '/api/auth' });
  res.clearCookie('sessionId', { path: '/' });
}

function loginResponse(res, user, req) {
  const payload = { sub: user.id, email: user.email, role: user.role };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(user.id);
  const sessionId = createSession(user.id, req.ip, req.headers['user-agent'] || '');
  res.cookie('sessionId', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  setAuthCookies(res, accessToken, refreshToken);
  res.json({ user: { id: user.id, email: user.email, role: user.role } });
}

export async function handleLogin(req, res, next) {
  try {
    const { email, password, totpCode } = req.body;
    const result = await authenticate(email, password, totpCode);
    if (result.mfaRequired) {
      return res.json({ mfaRequired: true, email: result.tempEmail });
    }
    loginResponse(res, result, req);
    logger.info({ userId: result.id }, 'Login successful');
  } catch (err) { next(err); }
}

export async function handleRegister(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await register({ email, password });
    loginResponse(res, user, req);
    logger.info({ userId: user.id }, 'Registration successful');
    res.status(201).json({ user });
  } catch (err) { next(err); }
}

export async function handleLogout(req, res, next) {
  try {
    const refreshToken = req.cookies?.refreshToken;
    if (refreshToken) revokeRefreshToken(refreshToken);
    else if (req.user?.id) revokeAllUserRefreshTokens(req.user.id);
    if (req.user?.id) deleteAllUserSessions(req.user.id);
    clearAuthCookies(res);
    logger.info('Logout successful');
    res.json({ message: 'Logged out.' });
  } catch (err) { next(err); }
}

export async function handleRefresh(req, res, next) {
  try {
    const old = req.cookies?.refreshToken;
    if (!old) return res.status(401).json({ error: 'Refresh token required.' });
    const stored = getStoredRefreshToken(old);
    if (!stored) { clearAuthCookies(res); return res.status(401).json({ error: 'Invalid or expired refresh token.' }); }
    const user = getUserById(stored.userId);
    if (!user) { revokeRefreshToken(old); clearAuthCookies(res); return res.status(401).json({ error: 'User not found.' }); }
    const newRefresh = rotateRefreshToken(old, user.id);
    const accessToken = generateAccessToken({ sub: user.id, email: user.email, role: user.role });
    setAuthCookies(res, accessToken, newRefresh);
    res.json({ user });
  } catch (err) { next(err); }
}

export async function handleMe(req, res) {
  const full = getUserById(req.user.id);
  res.json({ user: full });
}

export async function handleVerifyEmail(req, res, next) {
  try {
    const result = await verifyEmail(req.query.token);
    res.json({ message: 'Email verified.', user: result });
  } catch (err) { next(err); }
}

export async function handleForgotPassword(req, res, next) {
  try {
    const result = await forgotPassword(req.body.email);
    res.json(result);
  } catch (err) { next(err); }
}

export async function handleResetPassword(req, res, next) {
  try {
    const result = await resetPassword(req.body.token, req.body.password);
    if (result.userId) {
      revokeAllUserRefreshTokens(result.userId);
      deleteAllUserSessions(result.userId);
    }
    clearAuthCookies(res);
    res.json({ message: result.message });
  } catch (err) { next(err); }
}

export async function handleGenerateMFA(req, res, next) {
  try {
    const result = await generateMFASecret(req.user.id);
    res.json(result);
  } catch (err) { next(err); }
}

export async function handleEnableMFA(req, res, next) {
  try {
    const result = await enableMFA(req.user.id, req.body.code);
    res.json(result);
  } catch (err) { next(err); }
}

export async function handleDisableMFA(req, res, next) {
  try {
    const result = await disableMFA(req.user.id);
    res.json(result);
  } catch (err) { next(err); }
}

export async function handleSessions(req, res, next) {
  try {
    const sessions = getSessionsByUserId(req.user.id);
    res.json({ sessions });
  } catch (err) { next(err); }
}

export async function handleDeleteSession(req, res, next) {
  try {
    deleteSession(req.params.sessionId);
    res.json({ message: 'Session removed.' });
  } catch (err) { next(err); }
}

export async function handleLogoutAll(req, res, next) {
  try {
    revokeAllUserRefreshTokens(req.user.id);
    deleteAllUserSessions(req.user.id);
    clearAuthCookies(res);
    logger.info({ userId: req.user.id }, 'Logged out from all devices');
    res.json({ message: 'Logged out from all devices.' });
  } catch (err) { next(err); }
}

export async function handleBackupCodes(req, res, next) {
  try {
    const result = await regenerateBackupCodes(req.user.id);
    res.json(result);
  } catch (err) { next(err); }
}

export function handlePasswordPolicy(req, res) {
  res.json({ minLength: getMinPasswordLength() });
}
