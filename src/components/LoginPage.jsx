import { useState, useEffect, useRef, useCallback } from 'react'

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const MIN_PASSWORD_LENGTH = 12
const TIMEOUT_MS = 10000
const ALLOWED_REDIRECTS = ['/', '/dashboard', '/profile']

function validateEmail(value) {
  if (!value) return 'Email is required.'
  if (!EMAIL_REGEX.test(value)) return 'Enter a valid email address.'
  return ''
}

function validatePassword(value) {
  if (!value) return 'Password is required.'
  return ''
}

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [remember, setRemember] = useState(false)
  const [loading, setLoading] = useState(false)
  const [alert, setAlert] = useState(null)
  const [mfaStep, setMfaStep] = useState(false)
  const [totpCode, setTotpCode] = useState('')
  const [mfaEmail, setMfaEmail] = useState('')
  const [csrfToken, setCsrfToken] = useState(null)

  const emailError = email ? validateEmail(email) : ''
  const passwordError = password ? validatePassword(password) : ''
  const emailTouched = useRef(false)
  const passwordTouched = useRef(false)
  const abortRef = useRef(null)
  const totpRef = useRef(null)

  const isFormValid = csrfToken && !validateEmail(email) && !validatePassword(password)

  useEffect(() => {
    try {
      const saved = localStorage.getItem('rememberedEmail')
      if (saved) {
        setEmail(saved)
        setRemember(true)
      }
    } catch {}
    fetch('/api/auth/csrf-token', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setCsrfToken(d.csrfToken))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (mfaStep && totpRef.current) totpRef.current.focus()
  }, [mfaStep])

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault()
    setAlert(null)

    if (mfaStep) {
      if (!totpCode.trim()) {
        setAlert({ type: 'error', message: 'Enter your two-factor code.' })
        return
      }
      return submitLogin({ email: mfaEmail, password, totpCode: totpCode.trim() })
    }

    emailTouched.current = true
    passwordTouched.current = true
    if (!isFormValid) return

    submitLogin({ email: email.trim(), password })
  }, [email, password, remember, isFormValid, mfaStep, mfaEmail, totpCode, csrfToken])

  async function submitLogin(body) {
    setLoading(true)
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS)

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify(body),
        credentials: 'include',
        signal: controller.signal,
      })

      clearTimeout(timeoutId)
      setLoading(false)
      abortRef.current = null

      if (res.ok) {
        const data = await res.json()
        if (data.mfaRequired) {
          setMfaStep(true)
          setMfaEmail(data.email)
          return
        }
        try {
          if (remember) localStorage.setItem('rememberedEmail', email.trim())
          else localStorage.removeItem('rememberedEmail')
        } catch {}
        setAlert({ type: 'success', message: 'Authentication successful. Redirecting\u2026' })
        setTimeout(() => {
          const params = new URLSearchParams(window.location.search)
          const next = params.get('next')
          const redirect = next && ALLOWED_REDIRECTS.includes(next) ? next : '/dashboard'
          window.location.href = redirect
        }, 800)
      } else if (res.status === 423) {
        setAlert({ type: 'error', message: 'Account temporarily locked. Try again later.' })
      } else if (res.status === 429) {
        setAlert({ type: 'error', message: 'Too many attempts. Please wait before trying again.' })
      } else if (res.status >= 500) {
        setAlert({ type: 'error', message: 'Server error. Please try again later.' })
      } else {
        const data = await res.json().catch(() => ({}))
        setAlert({ type: 'error', message: data.error || 'Invalid email or password.' })
      }
    } catch (err) {
      clearTimeout(timeoutId)
      setLoading(false)
      abortRef.current = null
      if (err.name === 'AbortError') {
        setAlert({ type: 'error', message: 'Request timed out. Please try again.' })
      } else {
        setAlert({ type: 'error', message: 'Network error. Check your connection and try again.' })
      }
    }
  }

  function handleCancelMfa() {
    setMfaStep(false)
    setMfaEmail('')
    setTotpCode('')
    setAlert(null)
  }

  const showEmailError = emailTouched.current && emailError
  const showPasswordError = passwordTouched.current && passwordError

  if (mfaStep) {
    return (
      <>
        <div className="background" aria-hidden="true">
          <div className="spotlight" />
          <div className="vignette" />
        </div>
        <div className="container">
          <div className="card" role="region" aria-label="Two-factor authentication">
            <div className="card-header">
              <div className="brand" aria-hidden="true">
                <svg className="brand-icon" width="28" height="28" viewBox="0 0 32 32" fill="none">
                  <rect x="2" y="2" width="28" height="28" rx="8" stroke="currentColor" strokeWidth="2" />
                  <path d="M16 8a6 6 0 0 1 6 6v2h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h2v-2a6 6 0 0 1 6-6zm-4 8h8v-2a4 4 0 0 0-8 0v2z" fill="currentColor" opacity="0.9" />
                </svg>
                <span className="brand-name">Vault</span>
              </div>
              <h1 className="card-title">Two-factor required</h1>
              <p className="card-subtitle">Enter the code from your authenticator app</p>
            </div>

            <form onSubmit={handleSubmit} noValidate>
              <div className="field">
                <label htmlFor="totp" className="label">Authentication code</label>
                <input
                  type="text"
                  id="totp"
                  ref={totpRef}
                  className="input"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                  aria-describedby="totp-error"
                  placeholder="000000"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  disabled={loading}
                />
              </div>

              <button type="submit" className={`btn${loading ? ' loading' : ''}`} disabled={totpCode.length !== 6 || loading}>
                <span className="btn-text">Verify</span>
                <span className="btn-spinner" aria-hidden="true">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
                    <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                  </svg>
                </span>
              </button>

              <button type="button" className="btn btn--secondary" onClick={handleCancelMfa}>
                Cancel
              </button>

              {alert && (
                <div className={`form-alert form-alert--${alert.type}`} role="alert" aria-live="assertive">
                  {alert.message}
                </div>
              )}
            </form>
          </div>
        </div>
      </>
    )
  }

  return (
    <>
      <div className="background" aria-hidden="true">
        <div className="spotlight" />
        <div className="vignette" />
      </div>

      <div className="container">
        <div className="card" role="region" aria-label="Login form">
          <div className="card-header">
            <div className="brand" aria-hidden="true">
              <svg className="brand-icon" width="28" height="28" viewBox="0 0 32 32" fill="none">
                <rect x="2" y="2" width="28" height="28" rx="8" stroke="currentColor" strokeWidth="2" />
                <path d="M16 8a6 6 0 0 1 6 6v2h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h2v-2a6 6 0 0 1 6-6zm-4 8h8v-2a4 4 0 0 0-8 0v2z" fill="currentColor" opacity="0.9" />
              </svg>
              <span className="brand-name">Vault</span>
            </div>
            <h1 className="card-title">Welcome back</h1>
            <p className="card-subtitle">Sign in to your account to continue</p>
          </div>

            <form onSubmit={handleSubmit} noValidate>
            <div className="field">
              <label htmlFor="email" className="label">Email address</label>
              <input
                type="email"
                id="email"
                className="input"
                autoComplete="email"
                required
                aria-describedby="email-error"
                aria-invalid={showEmailError ? 'true' : 'false'}
                placeholder="you@example.com"
                spellCheck={false}
                autoFocus
                value={email}
                onChange={(e) => { setEmail(e.target.value); emailTouched.current = true }}
                onBlur={() => { emailTouched.current = true }}
                disabled={loading}
              />
              <div className="field-error" id="email-error" role="alert" aria-live="polite">
                {showEmailError ? emailError : ''}
              </div>
            </div>

            <div className="field">
              <label htmlFor="password" className="label">Password</label>
              <div className="password-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  className="input"
                  autoComplete="current-password"
                  required
                  minLength={MIN_PASSWORD_LENGTH}
                  aria-describedby="password-error"
                  aria-invalid={showPasswordError ? 'true' : 'false'}
                  placeholder={'\u2022'.repeat(12)}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); passwordTouched.current = true }}
                  onBlur={() => { passwordTouched.current = true }}
                  disabled={loading}
                />
                <button
                  type="button"
                  className="toggle-password"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-controls="password"
                  tabIndex={-1}
                  onClick={() => setShowPassword((prev) => !prev)}
                >
                  {showPassword ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="field-error" id="password-error" role="alert" aria-live="polite">
                {showPasswordError ? passwordError : ''}
              </div>
            </div>

            <div className="field-row">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                />
                <span className="checkbox-custom" aria-hidden="true">
                  <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                    <path d="M2.5 6L5 8.5L9.5 3.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </span>
                <span className="checkbox-text">Remember me</span>
              </label>
              <a href="/forgot-password" className="forgot-link">Forgot password?</a>
            </div>

            <button type="submit" className={`btn${loading ? ' loading' : ''}`} disabled={!isFormValid || loading}>
              <span className="btn-text">Sign In</span>
              <span className="btn-spinner" aria-hidden="true">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
                  <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                </svg>
              </span>
            </button>

            {alert && (
              <div className={`form-alert form-alert--${alert.type}`} role="alert" aria-live="assertive">
                {alert.message}
              </div>
            )}
          </form>

          <p className="card-footer">
            Don&apos;t have an account? <a href="/register">Create one</a>
          </p>
        </div>
      </div>
    </>
  )
}
