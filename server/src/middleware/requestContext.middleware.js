export default function requestContext(req, res, next) {
  req.clientIp = req.ip || req.connection?.remoteAddress || '';
  req.clientUA = req.headers['user-agent'] || '';
  next();
}
