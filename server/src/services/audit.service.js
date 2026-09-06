// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import logger from '../utils/logger.js';
import { query } from '../db/index.js';

export async function logAction({ userId, action, details, ip, userAgent, severity = 'info' }) {
  await query(
    'INSERT INTO audit_events (user_id, action, details, ip, user_agent, severity) VALUES ($1, $2, $3, $4, $5, $6)',
    [userId || null, action, details ? JSON.stringify(details) : null, ip, userAgent, severity],
  );
  const level = severity === 'high' ? 'warn' : 'info';
  logger[level]({ userId, action, details, ip }, `[AUDIT] ${action}`);
}

export async function getAuditLog(userId = null, limit = 50) {
  const params = [];
  let where = '';
  if (userId) {
    params.push(userId);
    where = 'WHERE user_id = $1';
  }
  params.push(limit);
  const { rows } = await query(
    `SELECT id, timestamp, user_id, action, details, ip, user_agent, severity
     FROM audit_events ${where}
     ORDER BY timestamp DESC, id DESC
     LIMIT $${params.length}`,
    params,
  );
  return rows.map((r) => ({
    timestamp: r.timestamp,
    userId: r.user_id,
    action: r.action,
    details: r.details,
    ip: r.ip,
    userAgent: r.user_agent,
    severity: r.severity,
  }));
}

export async function securityAlert({ type, email, userId, ip, details }) {
  logger.error(
    { securityEvent: type, email, userId, ip, details },
    `[SECURITY ALERT] ${type}: ${details}`
  );
  await logAction({
    userId,
    action: `SECURITY_ALERT:${type}`,
    details,
    ip,
    userAgent: 'system',
    severity: 'high',
  });
}