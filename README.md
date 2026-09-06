# Vault — Secure Login System

A production-grade authentication system built with React, Node.js, and Express. Hardened against 46 security and code-quality issues across 3 audit rounds.

## Features

**Security**
- Bcrypt password hashing (12 rounds) with HIBP breach checking (fail-closed)
- JWT access/refresh token rotation with HttpOnly cookies (SameSite=Strict)
- CSRF protection via Double Submit Cookie pattern (httpOnly cookie, 32-byte random)
- Multi-layered rate limiting: global (200/15min), login (20/15min), register (10/15min), forgot-password (3/15min per IP), reset (5/15min per IP), MFA, email verification
- Account lockout with exponential backoff (IP + email-level tracking, multi-IP detection)
- Email verification enforcement (stub email system for local development)
- Multi-factor authentication (TOTP) with backup recovery codes
- Session management: idle timeout (30min), absolute lifetime (24h), IP/user-agent binding, remote logout, ownership validation
- Input sanitization (HTML stripping, length limits)
- Helmet security headers with strict CSP (Google Fonts whitelisted)
- Pino structured logging to stdout (Vercel-compatible; no pivoted log files)
- Idempotent Postgres schema migrations (auto-run on server boot and in the Vercel function)

**Frontend**
- React 19 with Vite 8
- Accessible login, register, forgot/reset password, dashboard pages
- Real-time password strength meter (zxcvbn)
- Staggered reveal animations with reduced-motion support
- Responsive design (mobile, tablet, desktop)

## Getting Started

### Prerequisites

- Node.js >=20
- npm 9+

### Installation

```bash
# Clone the repository
git clone https://github.com/IbnAbubakri/secure-login-system.git
cd secure-login-system

# Install dependencies (postinstall auto-installs server deps)
npm install

# Configure environment
cp server/.env.example server/.env
# Edit server/.env — set a strong JWT_SECRET and a Postgres DATABASE_URL
```

### Postgres Setup

Storage is Postgres (Vercel Neon in production, any local Postgres for development). The idempotent
schema is applied automatically on server boot and inside the Vercel function, so just start the server:

```bash
cd server && npm install && npm run dev   # dev — auto-migrates; create your own account on register
```

Create a database matching your `DATABASE_URL` first (e.g. `createdb vault`).

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

### Production Build

```bash
npm run build           # Build frontend into dist/
npm run start --prefix server  # Start backend (also serves frontend static files)
```

### Deploy to Vercel

The Express API runs as a serverless function (`api/index.js`) and Vercel serves the static frontend.

1. Push to GitHub and import the repo in Vercel.
2. Provision Postgres (Vercel dashboard → **Storage** → create a **Neon** database).
3. Add these environment variables (Production + Preview/Development):
   - `DATABASE_URL` — Neon Postgres connection string
   - `JWT_SECRET` — long random string
   - `CORS_ORIGIN` — your Vercel app URL (e.g. `https://your-app.vercel.app`)
   - `NODE_ENV` = `production`
   - `PUBLIC_ORIGIN` — base URL used to build email-verification / reset links
     (e.g. `https://your-app.vercel.app`; defaults handled in dev)
4. Deploy (`vercel` or git push). The function auto-migrates the schema on first boot.
5. Verify: `https://your-app.vercel.app/api/health`.

No accounts are ever seeded — create your own via the register flow.

Caveats:
- Rate limiters use per-function-instance in-memory stores, so global/per-endpoint limits are weaker
  under serverless concurrency.
- bcrypt is a native module; the prebuilt binaries target common Vercel platforms and are expected
  to work, but this is untested in production.

## Architecture

```
secure-login-system/
├── src/                    # React frontend (Vite)
│   ├── components/         # Page components
│   ├── App.jsx             # Router configuration
│   └── index.css           # Global styles
├── server/                 # Express backend
│   ├── src/
│   │   ├── config/         # Environment + JWT secret auto-generation
│   │   ├── controllers/    # Route handlers
│   │   ├── db/             # Postgres pool + schema.sql (auto-migrated)
│   │   ├── middleware/      # Auth, CSRF, validation, error, requestContext
│   │   ├── routes/         # API route definitions with per-endpoint rate limiters
│   │   ├── services/       # Business logic (auth, tokens, audit)
│   │   ├── utils/          # Logger, AppError, randomToken
│   │   ├── app.js          # Express app setup
│   │   ├── index.js        # Entry point
│   │   └── app.js          # Express app setup
│   └── .env                # DATABASE_URL + JWT_SECRET (gitignored)
├── api/
│   └── index.js            # Vercel serverless function wrapper (auto-migrates)
├── vercel.json             # Vercel routing (API + SPA fallback)
├── package.json
└── README.md
```

## API Endpoints

| Method | Path | Auth | Rate Limit | Description |
|--------|------|------|------------|-------------|
| GET | `/api/auth/csrf-token` | — | — | Get CSRF token |
| GET | `/api/auth/password-policy` | — | — | Get password policy |
| POST | `/api/auth/register` | — | 10/15min | Create account (requires email verification) |
| POST | `/api/auth/login` | — | 20/15min | Sign in |
| POST | `/api/auth/logout` | Required | — | Sign out (deletes current session only) |
| POST | `/api/auth/refresh` | — | — | Rotate tokens (+ double-rotation detection) |
| GET | `/api/auth/me` | Required | — | Current user profile |
| GET | `/api/auth/verify-email` | — | 10/60min | Verify email |
| POST | `/api/auth/forgot-password` | — | 3/15min per IP | Request password reset |
| POST | `/api/auth/reset-password` | — | 5/15min per IP | Reset password |
| POST | `/api/auth/mfa/generate` | Required | 5/15min | Generate TOTP secret |
| POST | `/api/auth/mfa/enable` | Required | 10/15min | Enable MFA |
| POST | `/api/auth/mfa/disable` | Required | 10/15min | Disable MFA |
| POST | `/api/auth/mfa/backup-codes` | Required | 5/15min | Regenerate backup codes |
| GET | `/api/auth/sessions` | Required | — | List active sessions |
| DELETE | `/api/auth/sessions/:id` | Required | — | Remove session (ownership checked) |
| POST | `/api/auth/logout-all` | Required | — | Logout all devices |
| GET | `/api/health` | — | — | Health check |

## Security Checklist

### Authentication
- [x] Password hashing (bcrypt, 12 rounds)
- [x] JWT access (15min) + refresh (7d) token rotation
- [x] Refresh token double-rotation prevention
- [x] Secure HttpOnly cookies (SameSite=Strict, path scoped)
- [x] MFA (TOTP) + hashed backup recovery codes
- [x] MFA disable requires valid TOTP re-authentication
- [x] Generic error messages (no user enumeration)
- [x] Timing-safe login (dummy bcrypt comparison on unknown email)

### Rate Limiting & Lockout
- [x] Global API rate limit (200/15min)
- [x] Per-endpoint rate limiters (login, register, forgot-password, reset, MFA, verify-email)
- [x] Account lockout with exponential backoff
- [x] IP + email-level failed attempt tracking
- [x] Multi-IP attack detection + security alert
- [x] Forgot-password rate limited per IP
- [x] Reset-password rate limited per IP

### Session Management
- [x] IP and user-agent binding in JWT (enforced on every request)
- [x] Session idle timeout (30min) + absolute lifetime (24h)
- [x] Session ownership validation on every request
- [x] Session cleanup on token rotation
- [x] Refresh token reuse detected → revoke all tokens and sessions
- [x] Session deletion ownership check
- [x] Logout deletes only current session
- [x] Remote logout all devices

### CSRF
- [x] Double Submit Cookie pattern (httpOnly, 32-byte random)
- [x] Loading state prevents double-submit before token loads
- [x] No hidden `_csrf` input field (prevents DOM-based leakage)

### Input & Output
- [x] Input validation + HTML sanitization
- [x] Request body size limit (10kb)
- [x] 30-second HTTP request timeout
- [x] Helmet security headers + strict CSP
- [x] CORS whitelist
- [x] Password policy exposed without history/expiry info leakage

### Password Security
- [x] HIBP breached password check (fail-closed on API error)
- [x] Password complexity validation (min 12 chars, uppercase, lowercase, numbers, special)
- [x] Password history (cannot reuse last 5 passwords)
- [x] Password expiry (90 days)

### Logging & Monitoring
- [x] Structured audit log (Postgres `audit_events` table)
- [x] Pino structured logging to stdout (redact sensitive fields)
- [x] Security alert events (account locked, MFA changes, multi-IP attacks)
- [x] Graceful error classification (operational vs internal)

### Code Quality
- [x] Postgres storage (pooled queries, transactions, idempotent schema migration)
- [x] Shared `randomToken` utility (replaces 6 inline `crypto.randomBytes` calls)
- [x] Request context middleware (centralizes IP/UA extraction)
- [x] Named constants (replaces magic strings/numbers)
- [x] `engines.node >=20` in both package.jsons
- [x] Dead dependencies removed (`qrcode`, `@types/react`, `@types/react-dom`)
- [x] HIBP API fetch with 5-second timeout via `AbortSignal.timeout()`

### Remaining (outside scope)
- [ ] CAPTCHA / bot protection
- [ ] Security monitoring / alerting dashboard
- [ ] Persistent rate-limit store (Vercel serverless instances share no memory)

## License

MIT
