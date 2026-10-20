/**
 * Typed client for the CipherLab API.
 *
 * Every authenticated call attaches the Bearer token automatically; the
 * token itself is supplied by the auth store so components never handle it.
 */

export interface ApiErrorBody {
  code: string
  message: string
  traceId: string
}

export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly traceId: string

  constructor(status: number, body: ApiErrorBody) {
    super(body.message)
    this.name = 'ApiError'
    this.status = status
    this.code = body.code
    this.traceId = body.traceId
  }
}

let tokenProvider: () => string | null = () => null

/** Registered once at startup by the auth store. */
export function setTokenProvider(provider: () => string | null): void {
  tokenProvider = provider
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const token = tokenProvider()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const response = await fetch(path, { ...init, headers })
  if (response.status === 204) {
    return undefined as T
  }

  const text = await response.text()
  const body = text ? JSON.parse(text) : null
  if (!response.ok) {
    throw new ApiError(response.status, (body ?? {
      code: 'UNKNOWN',
      message: `Request failed with status ${response.status}`,
      traceId: 'none',
    }) as ApiErrorBody)
  }
  return body as T
}

const post = <T>(path: string, body?: unknown): Promise<T> =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
const get = <T>(path: string): Promise<T> => request<T>(path)

// ---------------------------------------------------------------- lab
// The lab endpoints are stateless demonstrations and need no auth.

export interface EncryptResponse {
  algorithm: string
  key: string
  nonce: string
  ciphertext: string
  tag: string
  combined: string
  securityNote: string
}

export interface DecryptResponse {
  algorithm: string
  plaintext: string
  authenticated: boolean
  note: string
}

export interface HashResponse {
  algorithm: string
  digest: string
}

export interface HmacResponse {
  algorithm: string
  mac: string
  note: string
}

export interface DiffieHellmanResponse {
  p: string
  g: string
  alicePrivate: string
  bobPrivate: string
  alicePublic: string
  bobPublic: string
  sharedSecret: string
  steps: string[]
  securityNote: string
}

export interface HkdfResponse {
  algorithm: string
  ikmB64: string
  saltB64: string
  info: string
  outputLength: number
  prkHex: string
  outputHex: string
  steps: string[]
  securityNote: string
}

export interface SignatureKeygenResponse {
  algorithm: string
  privateKey: string
  publicKey: string
  fingerprint: string
  securityNote: string
}

export interface SignatureResponse {
  algorithm: string
  signature: string
  messageSha256: string
}

export interface SignatureVerificationResponse {
  valid: boolean
  fingerprint: string
  explanation: string
}

export interface MitmResponse {
  mode: string
  participants: string[]
  sharedSecrets: Record<string, string>
  malloryCanRead: boolean
  substitutionDetected: boolean
  steps: string[]
  securityNote: string
}

export const lab = {
  encrypt: (plaintext: string) =>
    post<EncryptResponse>('/api/v1/lab/aes/encrypt', { plaintext }),
  decrypt: (key: string, nonce: string, ciphertext: string, tag: string) =>
    post<DecryptResponse>('/api/v1/lab/aes/decrypt', { key, nonce, ciphertext, tag }),
  hash: (input: string, algorithm: 'SHA-256' | 'SHA-512') =>
    post<HashResponse>('/api/v1/lab/hash', { input, algorithm }),
  hmac: (key: string, input: string) =>
    post<HmacResponse>('/api/v1/lab/hmac', { key, input }),
  diffieHellman: (p: string, g: string, alicePrivate: string, bobPrivate: string) =>
    post<DiffieHellmanResponse>('/api/v1/lab/diffie-hellman', { p, g, alicePrivate, bobPrivate }),
  hkdf: (ikm: string, salt: string, info: string, outputLength: number) =>
    post<HkdfResponse>('/api/v1/lab/hkdf', { ikm, salt, info, outputLength }),
  keygen: () => post<SignatureKeygenResponse>('/api/v1/lab/signatures/keygen'),
  sign: (message: string, privateKey: string) =>
    post<SignatureResponse>('/api/v1/lab/signatures/sign', { message, privateKey }),
  verify: (message: string, signature: string, publicKey: string) =>
    post<SignatureVerificationResponse>('/api/v1/lab/signatures/verify', {
      message,
      signature,
      publicKey,
    }),
  mitm: (mode: 'unauthenticated' | 'authenticated') =>
    post<MitmResponse>('/api/v1/lab/mitm/simulate', { mode }),
}

// ---------------------------------------------------------------- auth

export interface User {
  id: string
  username: string
  email: string
  createdAt: string
}

export interface LoginResponse {
  accessToken: string
  tokenType: string
  expiresInSeconds: number
  user: User
}

export const auth = {
  register: (username: string, email: string, password: string) =>
    post<User>('/api/v1/auth/register', { username, email, password }),
  login: (username: string, password: string) =>
    post<LoginResponse>('/api/v1/auth/login', { username, password }),
  me: () => get<User>('/api/v1/auth/me'),
}

// ---------------------------------------------------------------- identity

export interface IdentityKey {
  id: string
  userId: string
  keyType: string
  publicKey: string
  fingerprint: string
  keyVersion: number
  createdAt: string
  revoked: boolean
  revokedAt: string | null
}

export const identity = {
  publish: (keyType: string, publicKey: string) =>
    post<IdentityKey>('/api/v1/identity/keys', { keyType, publicKey }),
  listMine: () => get<IdentityKey[]>('/api/v1/identity/keys'),
  revoke: (keyId: string) => post<IdentityKey>(`/api/v1/identity/keys/${keyId}/revoke`),
  forUser: (userId: string) => get<IdentityKey[]>(`/api/v1/identity/users/${userId}/keys`),
}

// ---------------------------------------------------------------- messaging

export interface Conversation {
  id: string
  memberIds: string[]
  createdAt: string
}

export interface CryptoSession {
  id: string
  conversationId: string
  initiatorId: string
  responderId: string
  suite: string
  status: 'PENDING' | 'ACTIVE' | 'EXPIRED'
  createdAt: string
  expiresAt: string | null
}

export interface RelayMessage {
  id: string
  conversationId: string
  sessionId: string
  senderId: string
  sequenceNumber: number
  nonce: string
  ciphertext: string
  createdAt: string
}

export const messaging = {
  createConversation: (partnerId: string) =>
    post<Conversation>('/api/v1/conversations', { partnerId }),
  listConversations: () => get<Conversation[]>('/api/v1/conversations'),
  createSession: (conversationId: string, suite: string) =>
    post<CryptoSession>(`/api/v1/conversations/${conversationId}/sessions`, { suite }),
  getSession: (sessionId: string) => get<CryptoSession>(`/api/v1/sessions/${sessionId}`),
  activate: (sessionId: string) => post<CryptoSession>(`/api/v1/sessions/${sessionId}/activate`),
  relay: (sessionId: string, sequenceNumber: number, nonce: string, ciphertext: string) =>
    post<RelayMessage>(`/api/v1/sessions/${sessionId}/messages`, {
      sequenceNumber,
      nonce,
      ciphertext,
    }),
  listMessages: (conversationId: string) =>
    get<RelayMessage[]>(`/api/v1/conversations/${conversationId}/messages`),
}
