# Vault — Secure Login System

A production-grade authentication system built with React, Node.js, and Express, implementing 38 of 40 OWASP-inspired security controls.

## Features

**Security**
- Bcrypt password hashing (12 rounds) with HIBP breach checking
- JWT access/refresh token rotation with HttpOnly cookies
- CSRF protection via Double Submit Cookie pattern
- Rate limiting (login: 5/15min, password reset: 3/15min)
- Account lockout with exponential backoff
- Email verification enforcement
- Multi-factor authentication (TOTP) with backup recovery codes
- Session management (idle timeout, absolute lifetime, remote logout)
- Input sanitization (HTML stripping, length limits)
- Helmet security headers with strict CSP
- Pino structured logging with daily rotation

**Frontend**
- React 19 with Vite
- Accessible login, register, forgot/reset password, and dashboard pages
- Real-time password strength meter (zxcvbn)
- Staggered reveal animations with reduced-motion support
- Responsive design (mobile, tablet, desktop)

## Getting Started

### Prerequisites

- Node.js 18+
- npm 9+

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-org>/secure-login-system.git
cd secure-login-system

# Install dependencies
npm install
cd server && npm install && cd ..

# Configure environment
cp server/.env.example server/.env
# Edit server/.env — set a strong JWT_SECRET
```

### Development

Run both servers concurrently:

```bash
# Terminal 1 — Backend
cd server && npm run dev

# Terminal 2 — Frontend
npm run dev
```

The Vite dev server proxies `/api/*` to the backend on port 4000.

Open [http://localhost:5173](http://localhost:5173).

### Demo Credentials

```
Email:    demo@vault.dev
Password: password123
```

> **Note:** The demo account has email pre-verified. Change the password in production.

### Production Build

```bash
npm run build           # Build frontend
cd server && npm start  # Start backend (serves API only)
```

For production, deploy behind a TLS-terminating reverse proxy (Nginx, Caddy) and serve the `dist/` directory.

## Architecture

```
secure-login-system/
├── src/                    # React frontend (Vite)
│   ├── components/         # Page components
│   ├── App.jsx             # Router configuration
│   └── index.css           # Global styles
├── server/                 # Express backend
│   ├── src/
│   │   ├── config/         # Environment configuration
│   │   ├── controllers/    # Route handlers
│   │   ├── middleware/      # Auth, CSRF, validation, error handling
│   │   ├── routes/         # API route definitions
│   │   ├── services/       # Business logic (auth, tokens)
│   │   └── utils/          # Logger, AppError
│   └── data/               # JSON file storage (development only)
├── package.json
└── README.md
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/auth/csrf-token` | — | Get CSRF token |
| POST | `/api/auth/register` | — | Create account |
| POST | `/api/auth/login` | — | Sign in |
| POST | `/api/auth/logout` | Required | Sign out |
| POST | `/api/auth/refresh` | — | Rotate tokens |
| GET | `/api/auth/me` | Required | Current user |
| GET | `/api/auth/verify-email` | — | Verify email |
| POST | `/api/auth/forgot-password` | — | Request reset |
| POST | `/api/auth/reset-password` | — | Reset password |
| POST | `/api/auth/mfa/generate` | Required | Generate TOTP secret |
| POST | `/api/auth/mfa/enable` | Required | Enable MFA |
| POST | `/api/auth/mfa/disable` | Required | Disable MFA |
| POST | `/api/auth/mfa/backup-codes` | Required | Regenerate backup codes |
| GET | `/api/auth/sessions` | Required | List sessions |
| DELETE | `/api/auth/sessions/:id` | Required | Remove session |
| POST | `/api/auth/logout-all` | Required | Logout all devices |
| GET | `/api/auth/password-policy` | — | Get min password length |
| GET | `/api/health` | — | Health check |

## Security Checklist

- [x] Password hashing (bcrypt, 12 rounds)
- [x] Rate limiting (login, password reset)
- [x] Helmet security headers + strict CSP
- [x] CORS whitelist
- [x] CSRF Double Submit Cookie
- [x] Input validation + sanitization
- [x] JWT access (15min) + refresh (7d) tokens
- [x] Refresh token rotation + revocation
- [x] Secure HttpOnly cookies (SameSite=Strict)
- [x] Account lockout (exponential backoff)
- [x] Email verification enforcement
- [x] Password reset with token expiry
- [x] MFA (TOTP) + backup recovery codes
- [x] Session idle timeout (30min) + absolute lifetime (24h)
- [x] Structured audit logging with rotation
- [x] HIBP breached password check
- [x] Generic error messages (no enumeration)
- [ ] CAPTCHA / bot protection
- [ ] Security monitoring / alerting

## License

MIT
