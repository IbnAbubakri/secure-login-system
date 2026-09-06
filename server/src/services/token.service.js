// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import env from '../config/env.js';
import { query } from '../db/index.js';

export function generateAccessToken(payload) {
  return jwt.sign(payload, env.JWT_SECRET, { expiresIn: env.JWT_ACCESS_EXPIRES_IN });
}

export async function generateRefreshToken(userId) {
  const token = uuidv4();
  const expiresAt = new Date(Date.now() + parseDuration(env.JWT_REFRESH_EXPIRES_IN)).toISOString();
  await query(
    'INSERT INTO refresh_tokens (token, user_id, expires_at, rotated) VALUES ($1, $2, $3, false)',
    [token, userId, expiresAt],
  );
  return token;
}

export function verifyAccessToken(token) {
  return jwt.verify(token, env.JWT_SECRET);
}

export async function rotateRefreshToken(oldToken, userId) {
  const { rowCount } = await query('SELECT 1 FROM refresh_tokens WHERE token = $1', [oldToken]);
  if (rowCount === 0) return null;
  const newToken = uuidv4();
  const expiresAt = new Date(Date.now() + parseDuration(env.JWT_REFRESH_EXPIRES_IN)).toISOString();
  await query('UPDATE refresh_tokens SET rotated = true WHERE token = $1', [oldToken]);
  await query(
    'INSERT INTO refresh_tokens (token, user_id, expires_at, rotated) VALUES ($1, $2, $3, false)',
    [newToken, userId, expiresAt],
  );
  return newToken;
}

export async function revokeRefreshToken(token) {
  await query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
}

export async function revokeAllUserRefreshTokens(userId) {
  await query('DELETE FROM refresh_tokens WHERE user_id = $1', [userId]);
}

export async function getStoredRefreshToken(token) {
  const { rows } = await query(
    'SELECT token, user_id, expires_at, rotated FROM refresh_tokens WHERE token = $1',
    [token],
  );
  const found = rows[0];
  if (!found) return null;
  if (new Date(found.expires_at) < new Date()) {
    await revokeRefreshToken(token);
    return null;
  }
  return { token: found.token, userId: found.user_id, expiresAt: found.expires_at, rotated: found.rotated };
}

/* Session management */

export async function createSession(userId, ip, userAgent) {
  const now = new Date();
  const id = uuidv4();
  await query(
    'INSERT INTO sessions (id, user_id, created_at, last_activity, ip, user_agent) VALUES ($1, $2, $3, $3, $4, $5)',
    [id, userId, now.toISOString(), ip, userAgent],
  );
  return id;
}

export async function updateSessionActivity(sessionId) {
  await query('UPDATE sessions SET last_activity = now() WHERE id = $1', [sessionId]);
}

export async function checkSessionActivity(sessionId, idleMinutes) {
  const { rows } = await query(
    'SELECT EXTRACT(EPOCH FROM (now() - last_activity)) / 60 < $1 AS active FROM sessions WHERE id = $2',
    [idleMinutes, sessionId],
  );
  const row = rows[0];
  if (!row) return false;
  if (row.active) return true;
  await query('DELETE FROM sessions WHERE id = $1', [sessionId]);
  return false;
}

export async function getSessionsByUserId(userId) {
  const { rows } = await query(
    'SELECT id, created_at, last_activity, ip, user_agent FROM sessions WHERE user_id = $1 ORDER BY last_activity DESC',
    [userId],
  );
  return rows.map((s) => ({
    id: s.id,
    createdAt: s.created_at,
    lastActivity: s.last_activity,
    ip: s.ip,
    userAgent: s.user_agent,
  }));
}

export async function getSessionById(sessionId) {
  const { rows } = await query(
    'SELECT id, user_id, created_at, last_activity, ip, user_agent FROM sessions WHERE id = $1',
    [sessionId],
  );
  const s = rows[0];
  if (!s) return null;
  return {
    id: s.id,
    userId: s.user_id,
    createdAt: s.created_at,
    lastActivity: s.last_activity,
    ip: s.ip,
    userAgent: s.user_agent,
  };
}

export async function deleteSession(sessionId) {
  await query('DELETE FROM sessions WHERE id = $1', [sessionId]);
}

export async function deleteAllUserSessions(userId) {
  await query('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

function parseDuration(dur) {
  const match = dur.match(/^(\d+)([smhd])$/);
  if (!match) return 7 * 24 * 60 * 60 * 1000;
  const val = parseInt(match[1]);
  switch (match[2]) {
    case 's': return val * 1000;
    case 'm': return val * 60 * 1000;
    case 'h': return val * 60 * 60 * 1000;
    case 'd': return val * 24 * 60 * 60 * 1000;
    default: return 7 * 24 * 60 * 60 * 1000;
  }
}