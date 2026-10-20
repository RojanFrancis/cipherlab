import { useState } from 'react'
import { AuthProvider, useAuth } from './lib/auth'
import { Lab } from './lab/Lab'
import { Messenger } from './messaging/Messenger'
import './App.css'

type Tab = 'lab' | 'messenger'

/**
 * App shell: a two-tab workspace. The Lab is anonymous by design; the
 * Messenger gates on auth and shows the login form when signed out.
 */
export default function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  )
}

function Shell() {
  const [tab, setTab] = useState<Tab>('lab')
  const { user, logout } = useAuth()

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">🔐</span>
          <div>
            <h1>CipherLab</h1>
            <p className="tagline">see the math, break the crypto</p>
          </div>
        </div>

        <nav className="tabs">
          <button
            className={tab === 'lab' ? 'tab active' : 'tab'}
            onClick={() => setTab('lab')}
            type="button"
          >
            Crypto Lab
          </button>
          <button
            className={tab === 'messenger' ? 'tab active' : 'tab'}
            onClick={() => setTab('messenger')}
            type="button"
          >
            Secure Messenger
          </button>
        </nav>

        <div className="header-user">
          {user ? (
            <>
              <span className="whoami">{user.username}</span>
              <button className="btn btn-ghost" onClick={logout} type="button">
                Sign out
              </button>
            </>
          ) : (
            <span className="whoami muted">not signed in</span>
          )}
        </div>
      </header>

      <main className="app-main">{tab === 'lab' ? <Lab /> : <Messenger />}</main>
    </div>
  )
}
