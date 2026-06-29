import { useState } from 'react'

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [alert, setAlert] = useState(null)
  const [csrfToken, setCsrfToken] = useState('')

  const emailValid = EMAIL_REGEX.test(email)

  useEffect(() => {
    fetch('/api/auth/csrf-token', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setCsrfToken(d.csrfToken))
      .catch(() => {})
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    setAlert(null)

    if (!email.trim() || !emailValid) {
      setAlert({ type: 'error', message: 'Enter a valid email address.' })
      return
    }

    setLoading(true)
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
        credentials: 'include',
      })

      setLoading(false)
      const data = await res.json().catch(() => ({}))

      if (res.ok) {
        setAlert({ type: 'success', message: 'If that email exists, a reset link has been sent.' })
        setEmail('')
      } else {
        setAlert({ type: 'error', message: data.error || 'Something went wrong. Try again later.' })
      }
    } catch {
      setLoading(false)
      setAlert({ type: 'error', message: 'Network error. Check your connection.' })
    }
  }

  return (
    <>
      <div className="background" aria-hidden="true">
        <div className="spotlight" />
        <div className="vignette" />
      </div>

      <div className="container">
        <div className="card" role="region" aria-label="Forgot password">
          <div className="card-header">
            <div className="brand" aria-hidden="true">
              <svg className="brand-icon" width="28" height="28" viewBox="0 0 32 32" fill="none">
                <rect x="2" y="2" width="28" height="28" rx="8" stroke="currentColor" strokeWidth="2" />
                <path d="M16 8a6 6 0 0 1 6 6v2h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h2v-2a6 6 0 0 1 6-6zm-4 8h8v-2a4 4 0 0 0-8 0v2z" fill="currentColor" opacity="0.9" />
              </svg>
              <span className="brand-name">Vault</span>
            </div>
            <h1 className="card-title">Reset password</h1>
            <p className="card-subtitle">Enter your email and we&apos;ll send you a reset link</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <div className="field">
              <label htmlFor="forgot-email" className="label">Email address</label>
              <input
                type="email" id="forgot-email" className="input"
                autoComplete="email" required
                placeholder="you@example.com"
                spellCheck={false}
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
              />
            </div>

            <button type="submit" className={`btn${loading ? ' loading' : ''}`} disabled={!email.trim() || loading}>
              <span className="btn-text">Send Reset Link</span>
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
