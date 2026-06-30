import randomToken from '../utils/randomToken.js';

const COOKIE_NAME = 'csrf-token';
const HEADER_NAME = 'x-csrf-token';
const CSRF_TOKEN_LENGTH = 32;

export function csrfToken(req, res) {
  let token = req.cookies?.[COOKIE_NAME];
  if (!token || token.length < CSRF_TOKEN_LENGTH) {
    token = randomToken(CSRF_TOKEN_LENGTH);
  }
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
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
