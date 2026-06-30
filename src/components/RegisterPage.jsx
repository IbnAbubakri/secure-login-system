import { useState, useRef, useCallback } from 'react'
import zxcvbn from 'zxcvbn'

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const TIMEOUT_MS = 10000

function validateEmail(value) {
  if (!value) return 'Email is required.'
  if (!EMAIL_REGEX.test(value)) return 'Enter a valid email address.'
  return ''
}

function validatePassword(value, policy) {
  if (!value) return 'Password is required.'
  if (value.length < policy.minLength) return `Password must be at least ${policy.minLength} characters.`
  if (value.length > policy.maxLength) return `Password must not exceed ${policy.maxLength} characters.`
  const rules = []
  if ((value.match(/[A-Z]/g) || []).length < policy.minUppercase) rules.push(`${policy.minUppercase} uppercase`)
  if ((value.match(/[a-z]/g) || []).length < policy.minLowercase) rules.push(`${policy.minLowercase} lowercase`)
  if ((value.match(/[0-9]/g) || []).length < policy.minNumbers) rules.push(`${policy.minNumbers} number`)
  if ((value.match(/[^A-Za-z0-9]/g) || []).length < policy.minSpecialChars) rules.push(`${policy.minSpecialChars} special character`)
  if (rules.length) return `Must include at least ${rules.join(', ')}.`
  return ''
}

export default function RegisterPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [alert, setAlert] = useState(null)
  const [csrfToken, setCsrfToken] = useState(null)
  const [policy, setPolicy] = useState(null)
  const abortRef = useRef(null)

  useEffect(() => {
    fetch('/api/auth/csrf-token', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setCsrfToken(d.csrfToken))
      .catch(() => {})
    fetch('/api/auth/password-policy', { credentials: 'include' })
      .then((r) => r.json())
      .then((p) => setPolicy(p))
      .catch(() => {})
  }, [])

  const emailError = email ? validateEmail(email) : ''
  const passwordError = password && policy ? validatePassword(password, policy) : ''
  const confirmError = confirmPassword && password !== confirmPassword ? 'Passwords do not match.' : ''
  const emailTouched = useRef(false)
  const passwordTouched = useRef(false)
  const confirmTouched = useRef(false)

  const formValid = csrfToken && policy && !emailError && !passwordError && !confirmError && email && password && confirmPassword

  const strength = password ? zxcvbn(password) : null
  const strengthScore = strength ? strength.score : 0
  const strengthLabel = ['Worst', 'Bad', 'Weak', 'Good', 'Strong']

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault()
    setAlert(null)
    emailTouched.current = passwordTouched.current = confirmTouched.current = true
    if (!formValid) return

    setLoading(true)
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS)

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
        credentials: 'include',
        signal: controller.signal,
      })

      clearTimeout(timeoutId)
      setLoading(false)
      abortRef.current = null

      if (res.ok) {
        setAlert({ type: 'success', message: 'Account created. Redirecting\u2026' })
        setTimeout(() => { window.location.href = '/dashboard' }, 800)
      } else {
        const data = await res.json().catch(() => ({}))
        setAlert({ type: 'error', message: data.error || 'Registration failed.' })
      }
    } catch (err) {
      clearTimeout(timeoutId)
      setLoading(false)
      abortRef.current = null
      setAlert({ type: 'error', message: err.name === 'AbortError' ? 'Request timed out.' : 'Network error.' })
    }
  }, [email, password, formValid, csrfToken])

  return (
    <>
      <div className="background" aria-hidden="true">
        <div className="spotlight" />
        <div className="vignette" />
      </div>

      <div className="container">
        <div className="card" role="region" aria-label="Registration form">
          <div className="card-header">
            <div className="brand" aria-hidden="true">
              <svg className="brand-icon" width="28" height="28" viewBox="0 0 32 32" fill="none">
                <rect x="2" y="2" width="28" height="28" rx="8" stroke="currentColor" strokeWidth="2" />
                <path d="M16 8a6 6 0 0 1 6 6v2h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h2v-2a6 6 0 0 1 6-6zm-4 8h8v-2a4 4 0 0 0-8 0v2z" fill="currentColor" opacity="0.9" />
              </svg>
              <span className="brand-name">Vault</span>
            </div>
            <h1 className="card-title">Create account</h1>
            <p className="card-subtitle">Secure your data from day one</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <div className="field">
              <label htmlFor="reg-email" className="label">Email address</label>
              <input
                type="email" id="reg-email" className="input"
                autoComplete="email" required
                aria-describedby="reg-email-error"
                aria-invalid={emailTouched.current && emailError ? 'true' : 'false'}
                placeholder="you@example.com"
                spellCheck={false}
                autoFocus
                value={email}
                onChange={(e) => { setEmail(e.target.value); emailTouched.current = true }}
                onBlur={() => { emailTouched.current = true }}
                disabled={loading}
              />
              <div className="field-error" id="reg-email-error" role="alert" aria-live="polite">
                {emailTouched.current && emailError ? emailError : ''}
              </div>
            </div>

            <div className="field">
              <label htmlFor="reg-password" className="label">Password</label>
              <div className="password-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="reg-password" className="input"
                  autoComplete="new-password" required
                  minLength={policy?.minLength || 12}
                  aria-describedby="reg-password-error"
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
              <div className="field-error" id="reg-password-error" role="alert" aria-live="polite">
                {passwordTouched.current && passwordError ? passwordError : ''}
              </div>
            </div>

            <div className="field">
              <label htmlFor="reg-confirm" className="label">Confirm password</label>
              <input
                type="password" id="reg-confirm" className="input"
                autoComplete="new-password" required
                aria-describedby="reg-confirm-error"
                aria-invalid={confirmTouched.current && confirmError ? 'true' : 'false'}
                placeholder="Repeat password"
                value={confirmPassword}
                onChange={(e) => { setConfirmPassword(e.target.value); confirmTouched.current = true }}
                onBlur={() => { confirmTouched.current = true }}
                disabled={loading}
              />
              <div className="field-error" id="reg-confirm-error" role="alert" aria-live="polite">
                {confirmTouched.current && confirmError ? confirmError : ''}
              </div>
            </div>

            <button type="submit" className={`btn${loading ? ' loading' : ''}`} disabled={!formValid || loading}>
              <span className="btn-text">Create Account</span>
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
            Already have an account? <a href="/">Sign in</a>
          </p>
        </div>
      </div>
    </>
  )
}
