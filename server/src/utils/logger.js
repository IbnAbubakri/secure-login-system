import pino from 'pino';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import env from '../config/env.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const transport = pino.transport({
  targets: [
    ...(env.isDev()
      ? [{ target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' }, level: 'debug' }]
      : []),
    {
      target: 'pino-roll',
      options: {
        file: resolve(__dirname, '../../logs/app.log'),
        frequency: 'daily',
        mkdir: true,
      },
      level: 'info',
    },
  ],
});

const logger = pino(
  {
    level: env.isDev() ? 'debug' : 'info',
    redact: {
      paths: ['req.headers.cookie', 'req.headers.authorization', 'body.password', 'body.token'],
      censor: '[REDACTED]',
    },
  },
  transport,
);

export default logger;
