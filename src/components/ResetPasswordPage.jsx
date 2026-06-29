import { useState, useRef, useCallback } from 'react'
import zxcvbn from 'zxcvbn'

const MIN_PASSWORD_LENGTH = 12
const TIMEOUT_MS = 10000

export default function ResetPasswordPage() {
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [alert, setAlert] = useState(null)
  const [csrfToken, setCsrfToken] = useState('')
  const abortRef = useRef(null)

  useEffect(() => {
    fetch('/api/auth/csrf-token', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setCsrfToken(d.csrfToken))
      .catch(() => {})
  }, [])

  const params = new URLSearchParams(window.location.search)
  const token = params.get('token')

  const passwordError = password && password.length < MIN_PASSWORD_LENGTH
    ? `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`
    : ''
  const confirmError = confirmPassword && password !== confirmPassword ? 'Passwords do not match.' : ''
  const passwordTouched = useRef(false)
  const confirmTouched = useRef(false)

  const formValid = !passwordError && !confirmError && password && confirmPassword

  const strength = password ? zxcvbn(password) : null
  const strengthScore = strength ? strength.score : 0
  const strengthLabel = ['Worst', 'Bad', 'Weak', 'Good', 'Strong']

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault()
    setAlert(null)
    passwordTouched.current = confirmTouched.current = true
    if (!formValid || !token) return

    setLoading(true)
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS)

    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ token, password }),
        credentials: 'include',
        signal: controller.signal,
      })

      clearTimeout(timeoutId)
      setLoading(false)
      abortRef.current = null

      if (res.ok) {
        setAlert({ type: 'success', message: 'Password reset successful. Redirecting to sign in\u2026' })
        setTimeout(() => { window.location.href = '/' }, 2000)
      } else {
        const data = await res.json().catch(() => ({}))
        setAlert({ type: 'error', message: data.error || 'Reset failed. The link may have expired.' })
      }
    } catch (err) {
      clearTimeout(timeoutId)
      setLoading(false)
      abortRef.current = null
      setAlert({ type: 'error', message: err.name === 'AbortError' ? 'Request timed out.' : 'Network error.' })
    }
  }, [password, token, formValid])

  if (!token) {
    return (
      <>
        <div className="background" aria-hidden="true">
          <div className="spotlight" />
          <div className="vignette" />
        </div>
        <div className="container">
          <div className="card" role="region" aria-label="Invalid reset link">
            <div className="card-header">
              <h1 className="card-title">Invalid link</h1>
              <p className="card-subtitle">This reset link is missing or invalid.</p>
            </div>
            <p className="card-footer"><a href="/">Back to sign in</a></p>
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
        <div className="card" role="region" aria-label="Reset password">
          <div className="card-header">
            <div className="brand" aria-hidden="true">
              <svg className="brand-icon" width="28" height="28" viewBox="0 0 32 32" fill="none">
                <rect x="2" y="2" width="28" height="28" rx="8" stroke="currentColor" strokeWidth="2" />
                <path d="M16 8a6 6 0 0 1 6 6v2h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h2v-2a6 6 0 0 1 6-6zm-4 8h8v-2a4 4 0 0 0-8 0v2z" fill="currentColor" opacity="0.9" />
              </svg>
              <span className="brand-name">Vault</span>
            </div>
            <h1 className="card-title">Set new password</h1>
            <p className="card-subtitle">Choose a strong password for your account</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <div className="field">
              <label htmlFor="reset-password" className="label">New password</label>
              <div className="password-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="reset-password" className="input"
                  autoComplete="new-password" required
                  minLength={MIN_PASSWORD_LENGTH}
                  aria-describedby="reset-password-error"
                  aria-invalid={passwordTouched.current && passwordError ? 'true' : 'false'}
                  placeholder={'\u2022'.repeat(12)}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); passwordTouched.current = true }}
                  onBlur={() => { passwordTouched.current = true }}
                  disabled={loading}
                />
                <button
                  type="button" className="toggle-password"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
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
              {password && (
                <div className="strength-meter" aria-label={`Password strength: ${strengthLabel[strengthScore]}`}>
                  <div className="strength-bar">
                    <div className={`strength-fill strength-fill--${strengthScore}`} style={{ width: `${(strengthScore + 1) * 20}%` }} />
                  </div>
                  <span className="strength-label">{strengthLabel[strengthScore]}</span>
                </div>
              )}
              <div className="field-error" id="reset-password-error" role="alert" aria-live="polite">
                {passwordTouched.current && passwordError ? passwordError : ''}
              </div>
            </div>

            <div className="field">
              <label htmlFor="reset-confirm" className="label">Confirm password</label>
              <input
                type="password" id="reset-confirm" className="input"
                autoComplete="new-password" required
                aria-describedby="reset-confirm-error"
                aria-invalid={confirmTouched.current && confirmError ? 'true' : 'false'}
                placeholder="Repeat password"
                value={confirmPassword}
                onChange={(e) => { setConfirmPassword(e.target.value); confirmTouched.current = true }}
                onBlur={() => { confirmTouched.current = true }}
                disabled={loading}
              />
              <div className="field-error" id="reset-confirm-error" role="alert" aria-live="polite">
                {confirmTouched.current && confirmError ? confirmError : ''}
              </div>
            </div>

            <button type="submit" className={`btn${loading ? ' loading' : ''}`} disabled={!formValid || loading}>
              <span className="btn-text">Reset Password</span>
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
            <a href="/">Back to sign in</a>
          </p>
        </div>
      </div>
    </>
  )
}
