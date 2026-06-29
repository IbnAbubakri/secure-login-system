import logger from '../utils/logger.js';
import env from '../config/env.js';

export default function errorHandler(err, req, res, _next) {
  const statusCode = err.statusCode || 500;
  const message = err.isOperational ? err.message : 'Internal server error.';

  if (!err.isOperational) {
    logger.error({ err, req: { method: req.method, url: req.url } }, 'Unhandled error');
  }

  res.status(statusCode).json({
    error: message,
    ...(env.isDev() && !err.isOperational && { stack: err.stack }),
  });
}
