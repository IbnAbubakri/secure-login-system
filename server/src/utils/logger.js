// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import pino from 'pino';
import env from '../config/env.js';

const logger = pino({
  level: env.isDev() ? 'debug' : 'info',
  redact: {
    paths: ['req.headers.cookie', 'req.headers.authorization', 'body.password', 'body.token', 'body.resetToken', 'body.emailVerificationToken', 'body.code', 'body.totpCode'],
    censor: '[REDACTED]',
  },
  transport: env.isDev()
    ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' }, level: 'debug' }
    : undefined,
});

export default logger;