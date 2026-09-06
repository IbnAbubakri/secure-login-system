// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import { useEffect, useState } from 'react'

const ICON_PROPS = {
  width: 18,
  height: 18,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
}

const MailIcon = () => (
  <svg {...ICON_PROPS}>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <path d="m3 7 9 6 9-6" />
  </svg>
)

const LinkedInIcon = () => (
  <svg {...ICON_PROPS} fill="currentColor" stroke="none">
    <path d="M4.98 3.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5ZM3 9.5h4V21H3V9.5Zm6 0h3.8v1.6h.05c.53-1 1.83-2.05 3.77-2.05 4.03 0 4.78 2.65 4.78 6.1V21h-4v-5.3c0-1.26-.02-2.9-1.77-2.9-1.77 0-2.04 1.38-2.04 2.8V21H9V9.5Z" />
  </svg>
)

const WhatsappIcon = () => (
  <svg {...ICON_PROPS}>
    <path d="M12 3a9 9 0 0 0-7.8 13.5L3 21l4.6-1.2A9 9 0 1 0 12 3Z" />
    <path d="M9.5 8.5c0 4 3 7 6.5 7l1-2-2-1-1 .6c-.3-.7-1-1.4-1.7-1.7L12.6 11l-1-2-2 1Z" />
  </svg>
)

const PortfolioIcon = () => (
  <svg {...ICON_PROPS}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3a13 13 0 0 1 0 18M12 3a13 13 0 0 0 0 18" />
  </svg>
)

const GithubIcon = () => (
  <svg {...ICON_PROPS} fill="currentColor" stroke="none">
    <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.9-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02a9.55 9.55 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v1.57c0 .26.18.57.69.48A10 10 0 0 0 12 2Z" />
  </svg>
)

const CONTACTS = [
  { label: 'Email', value: 'faruqsuzay@gmail.com', href: 'mailto:faruqsuzay@gmail.com', icon: MailIcon },
  { label: 'LinkedIn', value: 'linkedin.com/in/ibnabubakri', href: 'https://www.linkedin.com/in/ibnabubakri', icon: LinkedInIcon },
  { label: 'WhatsApp', value: '+234 906 134 5507', href: 'https://wa.me/2349061345507', icon: WhatsappIcon },
  { label: 'Portfolio', value: 'abubakrifaaruqadebowaleresume.vercel.app', href: 'https://abubakrifaaruqadebowaleresume.vercel.app/', icon: PortfolioIcon },
  { label: 'GitHub', value: 'github.com/IbnAbubakri', href: 'https://github.com/IbnAbubakri', icon: GithubIcon },
]

export default function DashboardPage() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    function checkAuth() {
      return fetch('/api/auth/me', { credentials: 'include' })
        .then((res) => {
          if (!res.ok) throw new Error('Not authenticated')
          return res.json()
        })
        .then((data) => { if (!cancelled) setUser(data.user) })
        .catch(() => { if (!cancelled) window.location.href = '/' })
    }
    checkAuth().finally(() => { if (!cancelled) setLoading(false) })
    const interval = setInterval(checkAuth, 5000)
    const onVisibility = () => { if (document.visibilityState === 'visible') checkAuth() }
    document.addEventListener('visibilitychange', onVisibility)
    return () => { cancelled = true; clearInterval(interval); document.removeEventListener('visibilitychange', onVisibility) }
  }, [])

  function handleLogout() {
    fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
      .catch(() => {})
      .finally(() => { window.location.href = '/' })
  }

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="btn-spinner" style={{ display: 'flex', position: 'static', width: 24, height: 24 }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" stroke="var(--accent)" strokeWidth="3" opacity="0.25" />
            <path d="M12 2a10 10 0 0 1 10 10" stroke="var(--accent)" strokeWidth="3" strokeLinecap="round" />
          </svg>
        </div>
      </div>
    )
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="dashboard-brand" aria-hidden="true">
          <svg width="24" height="24" viewBox="0 0 32 32" fill="none">
            <rect x="2" y="2" width="28" height="28" rx="8" stroke="currentColor" strokeWidth="2" />
            <path d="M16 8a6 6 0 0 1 6 6v2h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h2v-2a6 6 0 0 1 6-6zm-4 8h8v-2a4 4 0 0 0-8 0v2z" fill="currentColor" opacity="0.9" />
          </svg>
          <span>Vault</span>
        </div>
        <button onClick={handleLogout} className="dashboard-logout">Sign out</button>
      </header>
      <main className="dashboard-main">
        <section className="dashboard-hero">
          <p className="dashboard-eyebrow">Welcome</p>
          <h1>Thank you for exploring Vault.</h1>
          <p>
            Vault is a production-style authentication demo built with care for security and usability.
            Your time here means a lot — if you have feedback, questions, or just want to say hello,
            I would be glad to hear from you.
          </p>
          <p className="dashboard-signature">— Abubakri Faaruq Adebowale</p>
          {user && <p className="dashboard-session">Signed in as <span>{user.email}</span></p>}
        </section>
        <section className="contact-card">
          <h2 className="contact-card-title">Connect with me</h2>
          <p className="contact-card-subtitle">Reach out through any of these channels.</p>
          <div className="contact-grid">
            {CONTACTS.map(({ label, value, href, icon: Icon }) => (
              <div key={label} className="contact-item">
                <span className="contact-item-label">
                  <Icon />
                  {label}
                </span>
                <a href={href} target="_blank" rel="noreferrer">{value}</a>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  )
}