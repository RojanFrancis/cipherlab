import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { auth, setTokenProvider } from './api'
import type { User } from './api'
import { AuthContext } from './useAuth'

/**
 * Auth state for the whole app.
 *
 * The token is kept in localStorage so a refresh survives, and every API
 * call reads it through the provider registered below — components never
 * touch the raw token. (For a real deployment you would weigh localStorage
 * against an httpOnly cookie; the lab keeps it visible so the JWT itself is
 * inspectable in the DevTools network tab.)
 *
 * The context and the `useAuth` hook live in `./useAuth` so this file
 * exports only the component — required for Fast Refresh.
 */

const STORAGE_KEY = 'cipherlab.token'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY))
  const [user, setUser] = useState<User | null>(null)

  // The API client pulls the token from here on every request.
  useEffect(() => {
    setTokenProvider(() => token)
  }, [token])

  // On load (and on token change), resolve who we are. An invalid or
  // expired token fails quietly — the user simply lands logged out.
  // `user` is already null when there is no token (initial state, and
  // logout clears it), so no synchronous setState is needed here.
  useEffect(() => {
    if (!token) {
      return
    }
    let cancelled = false
    auth
      .me()
      .then((me) => {
        if (!cancelled) setUser(me)
      })
      .catch(() => {
        if (!cancelled) {
          localStorage.removeItem(STORAGE_KEY)
          setToken(null)
          setUser(null)
        }
      })
    return () => {
      cancelled = true
    }
  }, [token])

  const login = useCallback(async (username: string, password: string) => {
    const result = await auth.login(username, password)
    localStorage.setItem(STORAGE_KEY, result.accessToken)
    setToken(result.accessToken)
    setUser(result.user)
  }, [])

  const register = useCallback(
    async (username: string, email: string, password: string) => {
      await auth.register(username, email, password)
      // Registration does not auto-login; log in explicitly so the flow
      // (and any error) is visible in the UI.
      await login(username, password)
    },
    [login],
  )

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY)
    setToken(null)
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({ user, token, login, register, logout }),
    [user, token, login, register, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
