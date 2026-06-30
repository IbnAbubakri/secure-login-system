import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import logger from '../utils/logger.js';
import { loadJSON, saveJSON } from '../utils/fileStore.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AUDIT_PATH = resolve(__dirname, '../../data/audit.json');

function loadAudit() {
  return loadJSON(AUDIT_PATH, []);
}

function saveAudit(entries) {
  const trimmed = entries.length > 10000 ? entries.slice(entries.length - 10000) : entries;
  saveJSON(AUDIT_PATH, trimmed);
}

export function logAction({ userId, action, details, ip, userAgent, severity = 'info' }) {
  const entry = {
    timestamp: new Date().toISOString(),
    userId,
    action,
    details,
    ip,
    userAgent,
    severity,
  };
  const log = loadAudit();
  log.push(entry);
  saveAudit(log);
  const level = severity === 'high' ? 'warn' : 'info';
  logger[level]({ userId, action, details, ip }, `[AUDIT] ${action}`);
}

export function getAuditLog(userId = null, limit = 50) {
  const log = loadAudit();
  const filtered = userId ? log.filter((e) => e.userId === userId) : log;
  return filtered.slice(-limit).reverse();
}

export function securityAlert({ type, email, userId, ip, details }) {
  logger.error(
    { securityEvent: type, email, userId, ip, details },
    `[SECURITY ALERT] ${type}: ${details}`
  );
  logAction({
    userId,
    action: `SECURITY_ALERT:${type}`,
    details,
    ip,
    userAgent: 'system',
    severity: 'high',
  });
}
