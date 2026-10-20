import { createContext, useContext } from 'react'
import type { User } from './api'

/**
 * The auth context and its accessor, kept in their own module so
 * `auth.tsx` exports only the `<AuthProvider>` component. Bundlers rely on
 * a file exporting components alone for Fast Refresh; co-locating the hook
 * would silently disable hot reload for the whole provider file.
 */

export interface AuthState {
  user: User | null
  token: string | null
  login: (username: string, password: string) => Promise<void>
  register: (username: string, email: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthState | null>(null)

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used inside <AuthProvider>')
  }
  return context
}
