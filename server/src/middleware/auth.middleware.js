import { verifyAccessToken } from '../services/token.service.js';
import { getUserById } from '../services/auth.service.js';
import { checkSessionActivity, updateSessionActivity, getSessionById } from '../services/token.service.js';
import AppError from '../utils/AppError.js';

const IDLE_TIMEOUT_MINUTES = 30;
const ABSOLUTE_LIFETIME_HOURS = 24;

export function authenticate(req, res, next) {
  const token = req.cookies?.accessToken;
  if (!token) return next(new AppError('Authentication required.', 401));

  try {
    const decoded = verifyAccessToken(token);
    const user = getUserById(decoded.sub);
    if (!user) return next(new AppError('User not found.', 401));

    const sessionId = req.cookies?.sessionId;
    if (sessionId) {
      if (!checkSessionActivity(sessionId, IDLE_TIMEOUT_MINUTES)) {
        return next(new AppError('Session expired due to inactivity.', 401));
      }
      const session = getSessionById(sessionId);
      if (session) {
        const ageHours = (Date.now() - new Date(session.createdAt).getTime()) / 3600000;
        if (ageHours > ABSOLUTE_LIFETIME_HOURS) {
          return next(new AppError('Session lifetime exceeded. Please sign in again.', 401));
        }
      }
      updateSessionActivity(sessionId);
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') return next(new AppError('Token expired.', 401));
    return next(new AppError('Invalid token.', 401));
  }
}
