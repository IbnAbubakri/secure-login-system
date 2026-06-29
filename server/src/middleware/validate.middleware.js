import AppError from '../utils/AppError.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD = 12;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;

function sanitize(val) {
  if (typeof val !== 'string') return '';
  return val.replace(/<[^>]*>/g, '').trim();
}

function commonValidation(email, password) {
  const errors = [];
  if (!email || typeof email !== 'string') errors.push('Email is required.');
  else if (email.length > MAX_EMAIL_LENGTH) errors.push('Email is too long.');
  else if (!EMAIL_REGEX.test(sanitize(email))) errors.push('Invalid email format.');
  if (password !== undefined) {
    if (!password || typeof password !== 'string') errors.push('Password is required.');
    else if (password.length > MAX_PASSWORD_LENGTH) errors.push('Password is too long.');
    else if (password.length < MIN_PASSWORD) errors.push(`Password must be at least ${MIN_PASSWORD} characters.`);
  }
  return errors;
}

export function validateLogin(req, res, next) {
  const errors = commonValidation(req.body.email);
  if (!req.body.password || typeof req.body.password !== 'string') {
    errors.push('Password is required.');
  }
  if (errors.length) return next(new AppError(errors.join(' '), 400));
  req.body.email = sanitize(req.body.email).toLowerCase();
  next();
}

export function validateRegister(req, res, next) {
  const errors = commonValidation(req.body.email, req.body.password);
  if (errors.length) return next(new AppError(errors.join(' '), 400));
  req.body.email = sanitize(req.body.email).toLowerCase();
  next();
}

export function validatePasswordReset(req, res, next) {
  const { token, password } = req.body;
  const errors = [];
  if (!token || typeof token !== 'string') errors.push('Reset token is required.');
  if (!password || typeof password !== 'string') errors.push('Password is required.');
  else if (password.length > MAX_PASSWORD_LENGTH) errors.push('Password is too long.');
  else if (password.length < MIN_PASSWORD) errors.push(`Password must be at least ${MIN_PASSWORD} characters.`);
  if (errors.length) return next(new AppError(errors.join(' '), 400));
  next();
}
