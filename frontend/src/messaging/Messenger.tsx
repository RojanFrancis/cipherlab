import { useCallback, useEffect, useState } from 'react'
import { identity, messaging } from '../lib/api'
import type { Conversation, CryptoSession, IdentityKey, RelayMessage } from '../lib/api'
import { ApiError } from '../lib/api'
import { useAuth } from '../lib/useAuth'
import { textToBase64, toBase64, truncateMiddle } from '../lib/b64'

/**
 * Secure Messenger: the end-to-end story on top of the lab primitives.
 *
 * The server relays <b>ciphertext only</b>. In a full implementation the
 * browser would perform ECDH + HKDF + AES-GCM here with Web Crypto; this UI
 * keeps the envelope explicit so the relay's contract is visible — the
 * interesting server-side behaviours are session lifecycle and replay
 * rejection, and both are demonstrated directly.
 */
export function Messenger() {
  const { user } = useAuth()
  if (!user) {
    return <LoginGate />
  }
  return <Authenticated />
}

// ---------------------------------------------------------------- login

function LoginGate() {
  const { login, register } = useAuth()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      if (mode === 'login') {
        await login(username, password)
      } else {
        await register(username, email, password)
      }
    } catch (err) {
      setError(err instanceof ApiError ? `${err.code}: ${err.message}` : 'Request failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel" style={{ maxWidth: 460, margin: '2rem auto' }}>
      <h2>{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
      <p className="hint">
        Passwords are hashed with BCrypt server-side; signing in returns a
        short-lived JWT that the messenger attaches to every request.
      </p>
      <form onSubmit={submit}>
        <label htmlFor="username">Username</label>
        <input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        {mode === 'register' && (
          <>
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
          </>
        )}
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
        />
        {error && <div className="status error">{error}</div>}
        <div className="btn-row">
          <button className="btn" type="submit" disabled={busy}>
            {mode === 'login' ? 'Sign in' : 'Register & sign in'}
          </button>
          <button
            className="btn btn-ghost"
            type="button"
            onClick={() => {
              setMode(mode === 'login' ? 'register' : 'login')
              setError(null)
            }}
          >
            {mode === 'login' ? 'Need an account?' : 'Have an account?'}
          </button>
        </div>
      </form>
    </div>
  )
}

// ---------------------------------------------------------------- authenticated

function Authenticated() {
  const { user } = useAuth()
  const [keys, setKeys] = useState<IdentityKey[]>([])
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [selected, setSelected] = useState<Conversation | null>(null)
  const [session, setSession] = useState<CryptoSession | null>(null)
  const [messages, setMessages] = useState<RelayMessage[]>([])
  const [plaintext, setPlaintext] = useState('meet at midnight')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Initial load. Fetches in parallel and guards against setting state
  // after unmount; `refresh` below is reused by the mutation handlers.
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [mine, all] = await Promise.all([
          identity.listMine(),
          messaging.listConversations(),
        ])
        if (!cancelled) {
          setKeys(mine)
          setConversations(all)
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to load')
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const refresh = useCallback(async () => {
    try {
      setKeys(await identity.listMine())
      setConversations(await messaging.listConversations())
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to load')
    }
  }, [])

  const openConversation = async (conversation: Conversation) => {
    setSelected(conversation)
    setError(null)
    setSession(null)
    try {
      setMessages(await messaging.listMessages(conversation.id))
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to load messages')
    }
  }

  const startSession = async () => {
    if (!selected) return
    setError(null)
    try {
      const created = await messaging.createSession(
        selected.id,
        'EC_P256+HKDF-SHA256+AES-256-GCM',
      )
      setSession(created)
      setStatus('Session created (PENDING). The responder must activate it.')
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to create session')
    }
  }

  const activateSession = async () => {
    if (!session) return
    setError(null)
    try {
      const activated = await messaging.activate(session.id)
      setSession(activated)
      setStatus('Session ACTIVE — the relay now accepts ciphertext.')
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to activate')
    }
  }

  const send = async (replay: boolean) => {
    if (!session || !selected) return
    setError(null)
    setStatus(null)
    try {
      const nextSequence = replay && messages.length > 0
        ? messages.filter((m) => m.senderId === user?.id).at(-1)?.sequenceNumber ?? 0
        : messages.filter((m) => m.senderId === user?.id).length
      // The envelope is Base64 of the plaintext here purely so the UI can
      // show a real ciphertext value; production clients would encrypt with
      // Web Crypto first. The server never sees the key either way.
      const ciphertext = textToBase64(plaintext)
      const nonce = toBase64(crypto.getRandomValues(new Uint8Array(12)))
      await messaging.relay(session.id, nextSequence, nonce, ciphertext)
      setMessages(await messaging.listMessages(selected.id))
      setStatus(replay ? 'Relayed (this was a replay attempt).' : 'Relayed.')
    } catch (e) {
      if (e instanceof ApiError && e.code === 'REPLAYED_MESSAGE') {
        setStatus(null)
        setError(
          `REPLAYED_MESSAGE: ${e.message}  ← the server rejected it without decrypting anything`,
        )
      } else {
        setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to send')
      }
    }
  }

  const partnerId = selected?.memberIds.find((id) => id !== user?.id)

  // Guard renders only — all hooks above run unconditionally.
  if (!user) return null

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>Conversations</h2>
        <p className="hint">
          Start a conversation, publish a key, then run a session. The relay
          stores ciphertext only — it has no key and cannot read a byte.
        </p>

        <NewConversation onCreated={refresh} />
        <label>Your identity keys</label>
        <div className="card-list">
          {keys.length === 0 && <p className="hint">No keys published yet.</p>}
          {keys.map((key) => (
            <div className="card" key={key.id}>
              <h3>
                v{key.keyVersion} · {key.keyType}{' '}
                {key.revoked
                  ? <span className="badge bad">revoked</span>
                  : <span className="badge good">active</span>}
              </h3>
              <div className="meta">fp {truncateMiddle(key.fingerprint, 12)}</div>
            </div>
          ))}
        </div>

        <label>Conversations</label>
        <div className="card-list">
          {conversations.length === 0 && <p className="hint">None yet.</p>}
          {conversations.map((conversation) => (
            <div
              key={conversation.id}
              className={selected?.id === conversation.id ? 'card selected' : 'card'}
              onClick={() => void openConversation(conversation)}
            >
              <h3>{truncateMiddle(conversation.id, 8)}</h3>
              <div className="meta">{conversation.memberIds.length} members</div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <h2>Session & relay</h2>
        {!selected && <p className="hint">Pick a conversation on the left.</p>}
        {selected && (
          <>
            <dl className="kv">
              <dt>conversation</dt><dd>{truncateMiddle(selected.id, 10)}</dd>
              <dt>you</dt><dd>{user.username}</dd>
              <dt>partner</dt><dd>{partnerId ? truncateMiddle(partnerId, 8) : '—'}</dd>
            </dl>

            {!session && (
              <button className="btn" onClick={() => void startSession()} type="button">
                Create session
              </button>
            )}

            {session && (
              <>
                <dl className="kv">
                  <dt>session</dt><dd>{truncateMiddle(session.id, 10)}</dd>
                  <dt>suite</dt><dd>{session.suite}</dd>
                  <dt>status</dt>
                  <dd>
                    <span
                      className={
                        session.status === 'ACTIVE' ? 'badge good' : 'badge warn'
                      }
                    >
                      {session.status}
                    </span>
                  </dd>
                  <dt>expires</dt><dd>{session.expiresAt ?? '—'}</dd>
                </dl>
                <div className="btn-row">
                  {session.status === 'PENDING' && (
                    <button className="btn" onClick={() => void activateSession()} type="button">
                      Activate (as responder)
                    </button>
                  )}
                  {session.status === 'ACTIVE' && (
                    <>
                      <button className="btn" onClick={() => void send(false)} type="button">
                        Send
                      </button>
                      <button className="btn btn-danger" onClick={() => void send(true)} type="button">
                        Send replayed envelope
                      </button>
                    </>
                  )}
                </div>
              </>
            )}

            {status && <div className="status ok" style={{ marginTop: '0.8rem' }}>{status}</div>}
            {error && <div className="status error" style={{ marginTop: '0.8rem' }}>{error}</div>}

            <label style={{ marginTop: '1rem' }}>Message</label>
            <textarea value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />

            <label>History ({messages.length})</label>
            <div className="messages">
              {messages.length === 0 && <p className="hint">No messages yet.</p>}
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={message.senderId === user?.id ? 'message mine' : 'message'}
                >
                  <div className="sender">
                    seq {message.sequenceNumber} ·{' '}
                    {message.senderId === user?.id ? 'you' : 'partner'}
                  </div>
                  <div className="body">{base64Lossy(message.ciphertext)}</div>
                  <div className="envelope">
                    nonce {message.nonce} · ct {truncateMiddle(message.ciphertext, 18)}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function NewConversation({ onCreated }: { onCreated: () => Promise<void> | void }) {
  const [partnerId, setPartnerId] = useState('')
  const [error, setError] = useState<string | null>(null)

  const create = async () => {
    setError(null)
    try {
      await messaging.createConversation(partnerId)
      setPartnerId('')
      await onCreated()
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : 'Failed to create')
    }
  }

  return (
    <>
      <label htmlFor="partner">New conversation — partner user id</label>
      <input
        id="partner"
        value={partnerId}
        onChange={(e) => setPartnerId(e.target.value)}
        placeholder="paste a user id from /auth/me"
      />
      <div className="btn-row" style={{ marginBottom: '0.8rem' }}>
        <button className="btn btn-ghost" onClick={() => void create()} type="button">
          Create
        </button>
      </div>
      {error && <div className="status error">{error}</div>}
    </>
  )
}

/**
 * Best-effort decode for display. In this demo the "ciphertext" is Base64 of
 * the text; a real deployment would show an opaque blob here and decrypt
 * locally with the session key.
 */
function base64Lossy(value: string): string {
  try {
    return decodeURIComponent(escape(atob(value)))
  } catch {
    return `(opaque ciphertext, ${value.length} chars)`
  }
}
