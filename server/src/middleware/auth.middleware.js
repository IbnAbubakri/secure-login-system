// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import { verifyAccessToken } from '../services/token.service.js';
import { getUserById } from '../services/auth.service.js';
import { checkSessionActivity, updateSessionActivity, getSessionById } from '../services/token.service.js';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';

const IDLE_TIMEOUT_MINUTES = 30;
const ABSOLUTE_LIFETIME_HOURS = 24;

export async function authenticate(req, res, next) {
  const token = req.cookies?.accessToken;
  if (!token) return next(new AppError('Authentication required.', 401));

  try {
    const decoded = verifyAccessToken(token);
    const user = await getUserById(decoded.sub);
    if (!user) return next(new AppError('User not found.', 401));

    const sessionId = decoded.sessionId;
    // IP / user-agent binding: token must have been issued for this client.
    if (decoded.ip && req.clientIp && decoded.ip !== req.clientIp) {
      logger.warn({ userId: decoded.sub }, 'JWT IP binding mismatch');
      return next(new AppError('Session invalid. Please sign in again.', 401));
    }
    if (decoded.ua && req.clientUA && decoded.ua !== req.clientUA) {
      logger.warn({ userId: decoded.sub }, 'JWT user-agent binding mismatch');
      return next(new AppError('Session invalid. Please sign in again.', 401));
    }
    if (sessionId) {
      const active = await checkSessionActivity(sessionId, IDLE_TIMEOUT_MINUTES);
      if (!active) {
        return next(new AppError('Session expired due to inactivity.', 401));
      }
      const session = await getSessionById(sessionId);
      if (!session) {
        return next(new AppError('Session invalid. Please sign in again.', 401));
      }
      if (session.userId !== decoded.sub) {
        logger.warn({ userId: decoded.sub, sessionUserId: session.userId }, 'Session user mismatch');
        return next(new AppError('Session invalid.', 401));
      }
      const ageHours = (Date.now() - new Date(session.createdAt).getTime()) / 3600000;
      if (ageHours > ABSOLUTE_LIFETIME_HOURS) {
        return next(new AppError('Session lifetime exceeded. Please sign in again.', 401));
      }
      await updateSessionActivity(sessionId);
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') return next(new AppError('Token expired.', 401));
    return next(new AppError('Invalid token.', 401));
  }
}
