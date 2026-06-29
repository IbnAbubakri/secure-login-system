import crypto from 'crypto';

const COOKIE_NAME = 'csrf-token';
const HEADER_NAME = 'x-csrf-token';

export function csrfToken(req, res) {
  let token = req.cookies?.[COOKIE_NAME];
  if (!token || token.length < 32) {
    token = crypto.randomBytes(32).toString('hex');
  }
  res.cookie(COOKIE_NAME, token, {
    httpOnly: false,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.json({ csrfToken: token });
}

export function validateCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const cookieToken = req.cookies?.[COOKIE_NAME];
  const headerToken = req.headers[HEADER_NAME];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid CSRF token.' });
  }
  next();
}
