import AppError from '../utils/AppError.js';
import { getPasswordPolicy, validatePasswordComplexity } from '../services/auth.service.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254;

function sanitize(val) {
  if (typeof val !== 'string') return '';
  return val.replace(/<[^>]*>/g, '').trim();
}

function commonValidation(email, password) {
  const policy = getPasswordPolicy();
  const errors = [];
  if (!email || typeof email !== 'string') errors.push('Email is required.');
  else if (email.length > MAX_EMAIL_LENGTH) errors.push('Email is too long.');
  else if (!EMAIL_REGEX.test(sanitize(email))) errors.push('Invalid email format.');
  if (password !== undefined) {
    if (!password || typeof password !== 'string') errors.push('Password is required.');
    else if (password.length > policy.maxLength) errors.push('Password is too long.');
    else errors.push(...validatePasswordComplexity(password));
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
  else errors.push(...validatePasswordComplexity(password));
  if (errors.length) return next(new AppError(errors.join(' '), 400));
  next();
}
