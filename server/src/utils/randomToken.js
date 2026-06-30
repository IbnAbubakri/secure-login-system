import crypto from 'crypto';

export default function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}
