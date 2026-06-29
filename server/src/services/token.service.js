import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import env from '../config/env.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REFRESH_PATH = resolve(__dirname, '../../data/refresh-tokens.json');
const SESSIONS_PATH = resolve(__dirname, '../../data/sessions.json');

function loadJSON(path, fallback) {
  if (!existsSync(path)) return fallback;
  try { return JSON.parse(readFileSync(path, 'utf-8')); }
  catch { return fallback; }
}
function saveJSON(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8');
}

function loadRT() { return loadJSON(REFRESH_PATH, []); }
function saveRT(t) { saveJSON(REFRESH_PATH, t); }
function loadSessions() { return loadJSON(SESSIONS_PATH, []); }
function saveSessions(s) { saveJSON(SESSIONS_PATH, s); }

export function generateAccessToken(payload) {
  return jwt.sign(payload, env.JWT_SECRET, { expiresIn: env.JWT_ACCESS_EXPIRES_IN });
}

export function generateRefreshToken(userId) {
  const token = uuidv4();
  const expiresAt = new Date(Date.now() + parseDuration(env.JWT_REFRESH_EXPIRES_IN)).toISOString();
  const tokens = loadRT();
  tokens.push({ token, userId, expiresAt });
  saveRT(tokens);
  return token;
}

export function verifyAccessToken(token) {
  return jwt.verify(token, env.JWT_SECRET);
}

export function rotateRefreshToken(oldToken, userId) {
  const tokens = loadRT();
  saveRT(tokens.filter((t) => t.token !== oldToken));
  return generateRefreshToken(userId);
}

export function revokeRefreshToken(token) {
  saveRT(loadRT().filter((t) => t.token !== token));
}

export function revokeAllUserRefreshTokens(userId) {
  saveRT(loadRT().filter((t) => t.userId !== userId));
}

export function getStoredRefreshToken(token) {
  const tokens = loadRT();
  const found = tokens.find((t) => t.token === token);
  if (!found) return null;
  if (new Date(found.expiresAt) < new Date()) {
    revokeRefreshToken(token);
    return null;
  }
  return found;
}

/* Session management */

export function createSession(userId, ip, userAgent) {
  const sessions = loadSessions();
  const now = new Date();
  const id = uuidv4();
  sessions.push({
    id,
    userId,
    createdAt: now.toISOString(),
    lastActivity: now.toISOString(),
    ip,
    userAgent,
  });
  saveSessions(sessions);
  return id;
}

export function updateSessionActivity(sessionId) {
  const sessions = loadSessions();
  const s = sessions.find((s) => s.id === sessionId);
  if (s) { s.lastActivity = new Date().toISOString(); saveSessions(sessions); }
}

export function checkSessionActivity(sessionId, idleMinutes) {
  const sessions = loadSessions();
  const s = sessions.find((s) => s.id === sessionId);
  if (!s) return false;
  const elapsed = (new Date() - new Date(s.lastActivity)) / 60000;
  if (elapsed > idleMinutes) {
    saveSessions(sessions.filter((x) => x.id !== sessionId));
    return false;
  }
  return true;
}

export function getSessionsByUserId(userId) {
  return loadSessions().filter((s) => s.userId === userId);
}

export function getSessionById(sessionId) {
  return loadSessions().find((s) => s.id === sessionId) || null;
}

export function deleteSession(sessionId) {
  saveSessions(loadSessions().filter((s) => s.id !== sessionId));
}

export function deleteAllUserSessions(userId) {
  saveSessions(loadSessions().filter((s) => s.userId !== userId));
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


