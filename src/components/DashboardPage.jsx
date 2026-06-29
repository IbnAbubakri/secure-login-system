import { useEffect, useState } from 'react'

export default function DashboardPage() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/auth/me', { credentials: 'include' })
      .then((res) => {
        if (!res.ok) throw new Error('Not authenticated')
        return res.json()
      })
      .then((data) => setUser(data.user))
      .catch(() => { window.location.href = '/' })
      .finally(() => setLoading(false))
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
        <h1>Welcome to the dashboard</h1>
        {user && <p className="dashboard-email">{user.email}</p>}
      </main>
    </div>
  )
}
