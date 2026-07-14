// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

export default function requestContext(req, res, next) {
  req.clientIp = req.ip || req.connection?.remoteAddress || '';
  req.clientUA = req.headers['user-agent'] || '';
  next();
}
