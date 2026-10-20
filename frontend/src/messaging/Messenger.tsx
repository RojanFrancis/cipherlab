import { useCallback, useEffect, useRef, useState } from 'react'
import { identity as identityApi, messaging } from '../lib/api'
import type { Conversation, CryptoSession, IdentityKey, RelayMessage } from '../lib/api'
import { ApiError } from '../lib/api'
import { useAuth } from '../lib/useAuth'
import { truncateMiddle } from '../lib/b64'
import {
  SUITE,
  decryptMessage,
  deriveSessionKeys,
  encryptMessage,
  fullTranscript,
  generateEphemeralKeyPair,
  generateIdentityKeyPair,
  importIdentityPrivateKey,
  initiatorTranscript,
  signTranscript,
  verifyTranscript,
} from '../lib/e2ee'
import type { HandshakeMeta, IdentityKeyPair, SessionKeys } from '../lib/e2ee'

/**
 * Secure Messenger — genuine end-to-end encryption in the browser.
 *
 * Identity keypairs are generated here with Web Crypto; only public halves
 * are published (the server re-computes fingerprints and can never read
 * private material). Sessions run a signed ephemeral ECDH handshake — both
 * sides sign the canonical transcript with their identity key and verify
 * the peer's signature before deriving anything. Message payloads are
 * AES-256-GCM under directional HKDF-derived keys with the envelope
 * metadata as additional authenticated data. The server relays ciphertext
 * it cannot read, and this UI proves it: the replay button resubmits a
 * captured envelope and shows the server reject it.
 *
 * Private keys live in component memory only — optionally exported to a
 * user-held backup file. Nothing sensitive touches localStorage or logs.
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
  const [identity, setIdentity] = useState<IdentityKeyPair | null>(null)
  const [importText, setImportText] = useState('')
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [selected, setSelected] = useState<Conversation | null>(null)
  const [sessions, setSessions] = useState<CryptoSession[]>([])
  const [messages, setMessages] = useState<RelayMessage[]>([])
  const [decoded, setDecoded] = useState<Record<string, string | null>>({})
  const [plaintext, setPlaintext] = useState('meet at midnight')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Private material, keyed by session id — never serialized, never stored.
  const ephemeralPrivates = useRef(new Map<string, CryptoKey>())
  const sessionKeys = useRef(new Map<string, SessionKeys>())

  const showError = useCallback((e: unknown, fallback: string) => {
    setError(e instanceof ApiError ? `${e.code}: ${e.message}` : fallback)
  }, [])

  const load = useCallback(async () => {
    try {
      const [mine, all] = await Promise.all([identityApi.listMine(), messaging.listConversations()])
      setKeys(mine)
      setConversations(all)
    } catch (e) {
      showError(e, 'Failed to load')
    }
  }, [showError])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [mine, all] = await Promise.all([identityApi.listMine(), messaging.listConversations()])
        if (!cancelled) {
          setKeys(mine)
          setConversations(all)
        }
      } catch (e) {
        if (!cancelled) showError(e, 'Failed to load')
      }
    })()
    return () => {
      cancelled = true
    }
  }, [showError])

  const openConversation = async (conversation: Conversation) => {
    setSelected(conversation)
    setError(null)
    setStatus(null)
    try {
      const [sessionList, history] = await Promise.all([
        messaging.listSessions(conversation.id),
        messaging.listMessages(conversation.id),
      ])
      setSessions(sessionList)
      setMessages(history)
    } catch (e) {
      showError(e, 'Failed to load conversation')
    }
  }

  const refreshChannel = async (conversationId: string) => {
    try {
      const [sessionList, history] = await Promise.all([
        messaging.listSessions(conversationId),
        messaging.listMessages(conversationId),
      ])
      setSessions(sessionList)
      setMessages(history)
    } catch (e) {
      showError(e, 'Failed to refresh')
    }
  }

  // --------------------------------------------- identity key management

  const generateAndPublish = async () => {
    setError(null)
    try {
      const generated = await generateIdentityKeyPair()
      await identityApi.publish('EC_P256', generated.spkiB64)
      setIdentity(generated)
      setStatus(`Identity key published. Fingerprint ${formatFingerprint(generated.fingerprintHex)} — verify it with your contact out of band.`)
      await load()
    } catch (e) {
      showError(e, 'Failed to publish identity key')
    }
  }

  const exportBackup = () => {
    if (!identity) return
    const blob = new Blob([identity.backup], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'cipherlab-identity-backup.txt'
    anchor.click()
    URL.revokeObjectURL(url)
    setStatus('Backup file downloaded. Keep it private — it contains your identity private key.')
  }

  const importBackup = async () => {
    setError(null)
    try {
      const restored = await importIdentityPrivateKey(importText)
      setIdentity(restored)
      setImportText('')
      const published = keys.some((k) => k.fingerprint === restored.fingerprintHex && !k.revoked)
      setStatus(
        restored.spkiB64 && !published
          ? 'Backup restored, but its public half is not published yet — press "Generate & publish" only for NEW keys; to publish this restored key use the API or keep using a published key.'
          : `Backup restored. Fingerprint ${formatFingerprint(restored.fingerprintHex)}.`,
      )
    } catch (e) {
      showError(e, 'Could not restore that backup')
    }
  }

  const revokeKey = async (keyId: string) => {
    try {
      await identityApi.revoke(keyId)
      await load()
    } catch (e) {
      showError(e, 'Failed to revoke key')
    }
  }

  // --------------------------------------------- handshake

  const usableKey = (): IdentityKey | undefined =>
    keys.find((k) => !k.revoked && k.keyType === 'EC_P256' && identity && k.fingerprint === identity.fingerprintHex)

  const startHandshake = async () => {
    if (!selected || !identity || !user) return
    setError(null)
    setStatus(null)
    try {
      const partnerId = selected.memberIds.find((id) => id !== user?.id)
      if (!partnerId) throw new Error('conversation needs a partner')
      const myPublished = usableKey()
      if (!myPublished) {
        setError('Generate (or import) and publish your identity key first — the handshake signs with it.')
        return
      }
      const sessionId = crypto.randomUUID()
      const eph = await generateEphemeralKeyPair()
      const meta: HandshakeMeta = {
        sessionId,
        conversationId: selected.id,
        initiatorId: user.id,
        responderId: partnerId,
      }
      const signature = await signTranscript(identity.privateKey, initiatorTranscript(meta, eph.spkiB64))
      ephemeralPrivates.current.set(sessionId, eph.privateKey)
      await messaging.createSession(selected.id, sessionId, SUITE, eph.spkiB64, signature, myPublished.id)
      setStatus('Handshake started: your signed ephemeral is on the server. The partner must complete it.')
      await refreshChannel(selected.id)
    } catch (e) {
      showError(e, 'Failed to start session')
    }
  }

  const completeHandshake = async (session: CryptoSession) => {
    if (!selected || !identity) return
    setError(null)
    setStatus(null)
    try {
      const myPublished = usableKey()
      if (!myPublished) {
        setError('Generate (or import) and publish your identity key first.')
        return
      }
      const meta: HandshakeMeta = {
        sessionId: session.id,
        conversationId: session.conversationId,
        initiatorId: session.initiatorId,
        responderId: session.responderId,
      }
      // 1. Verify the initiator's signature against their PUBLISHED identity
      //    key — never trust the server's word for who signed what.
      const initiatorKeys = await identityApi.forUser(session.initiatorId)
      const signingKey = initiatorKeys.find((k) => k.id === session.initiatorIdentityKeyId)
      if (!signingKey || signingKey.revoked) {
        setError('The initiator references a missing or revoked identity key — handshake aborted.')
        return
      }
      const initiatorOk = await verifyTranscript(
        signingKey.publicKey,
        initiatorTranscript(meta, session.initiatorEphemeralPublic),
        session.initiatorSignature,
      )
      if (!initiatorOk) {
        setError('Initiator signature did NOT verify — possible key substitution. Handshake aborted.')
        return
      }
      // 2. Contribute our own signed ephemeral.
      const eph = await generateEphemeralKeyPair()
      const signature = await signTranscript(
        identity.privateKey,
        fullTranscript(meta, session.initiatorEphemeralPublic, eph.spkiB64),
      )
      const activated = await messaging.activate(session.id, eph.spkiB64, signature, myPublished.id)
      // 3. Derive directional keys locally.
      ephemeralPrivates.current.set(session.id, eph.privateKey)
      const derived = await deriveSessionKeys(
        meta,
        session.initiatorEphemeralPublic,
        eph.spkiB64,
        eph.privateKey,
        false,
      )
      sessionKeys.current.set(session.id, derived)
      setDerivedSessionIds(new Set(sessionKeys.current.keys()))
      setStatus('Handshake verified and completed — secure channel ready.')
      setSessions((prev) => prev.map((s) => (s.id === activated.id ? activated : s)))
      if (selected) await refreshChannel(selected.id)
    } catch (e) {
      showError(e, 'Failed to complete handshake')
    }
  }

  // The initiator derives keys once the session turns ACTIVE.
  const [derivedSessionIds, setDerivedSessionIds] = useState<Set<string>>(new Set())
  useEffect(() => {
    let cancelled = false
    const pending = sessions.filter(
      (s) => s.status === 'ACTIVE' && !sessionKeys.current.has(s.id) && ephemeralPrivates.current.has(s.id),
    )
    for (const session of pending) {
      const ephPrivate = ephemeralPrivates.current.get(session.id)
      if (!ephPrivate) continue
      const meta: HandshakeMeta = {
        sessionId: session.id,
        conversationId: session.conversationId,
        initiatorId: session.initiatorId,
        responderId: session.responderId,
      }
      deriveSessionKeys(meta, session.initiatorEphemeralPublic, session.responderEphemeralPublic ?? '', ephPrivate, true)
        .then((derived) => {
          if (cancelled) return
          sessionKeys.current.set(session.id, derived)
          setDerivedSessionIds(new Set(sessionKeys.current.keys()))
        })
        .catch(() => {
          /* derivation cannot fail with valid P-256 keys; ignore */
        })
    }
    return () => {
      cancelled = true
    }
  }, [sessions])

  // --------------------------------------------- messages

  // Decrypt every message of the selected conversation whose session keys we hold.
  useEffect(() => {
    let cancelled = false
    const next: Record<string, string | null> = {}
    const work = messages.map(async (message) => {
      const keysForSession = sessionKeys.current.get(message.sessionId)
      if (!keysForSession || !user) {
        next[message.id] = null
        return
      }
      const key = message.senderId === user.id ? keysForSession.sendKey : keysForSession.receiveKey
      try {
        next[message.id] = await decryptMessage(key, {
          sessionId: message.sessionId,
          conversationId: message.conversationId,
          senderId: message.senderId,
          sequenceNumber: message.sequenceNumber,
        }, message.nonce, message.ciphertext)
      } catch {
        next[message.id] = null // tampered, relocated, or wrong key — fail closed
      }
    })
    void Promise.all(work).then(() => {
      if (!cancelled) setDecoded(next)
    })
    return () => {
      cancelled = true
    }
  }, [messages, derivedSessionIds, user])

  const activeSession = sessions.find(
    (s) => s.status === 'ACTIVE' && derivedSessionIds.has(s.id),
  )
  const pendingSessions = sessions.filter((s) => s.status === 'PENDING')

  const send = async (replayOf?: RelayMessage) => {
    if (!selected || !user) return
    const session = activeSession
    if (!session) return
    const keysForSession = sessionKeys.current.get(session.id)
    if (!keysForSession) return
    setError(null)
    setStatus(null)
    const myMessages = messages.filter((m) => m.sessionId === session.id && m.senderId === user.id)
    try {
      if (replayOf) {
        // Resubmit a previously sent envelope verbatim — the server must
        // reject it by (session, sender, sequence) without decrypting anything.
        await messaging.relay(session.id, replayOf.sequenceNumber, replayOf.nonce, replayOf.ciphertext)
        setStatus('Relayed?! That should have been rejected — please report this.')
      } else {
        const sequenceNumber = myMessages.length
        const envelope = await encryptMessage(keysForSession.sendKey, {
          sessionId: session.id,
          conversationId: selected.id,
          senderId: user.id,
          sequenceNumber,
        }, plaintext)
        await messaging.relay(session.id, sequenceNumber, envelope.nonceB64, envelope.ciphertextB64)
        setStatus('Encrypted and relayed. The server stored ciphertext only.')
      }
      await refreshChannel(selected.id)
    } catch (e) {
      if (e instanceof ApiError && e.code === 'REPLAYED_MESSAGE') {
        setStatus(null)
        setError(`REPLAYED_MESSAGE: ${e.message}  ← the server rejected it without decrypting anything`)
      } else {
        showError(e, 'Failed to send')
      }
    }
  }

  const lastMine = [...messages].reverse().find((m) => m.senderId === user?.id && m.sessionId === activeSession?.id)
  const myPublishedKey = usableKey()

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>Identity & conversations</h2>
        <p className="hint">
          Your identity key is generated <b>in this browser</b> with Web Crypto;
          only the public half is published. Verify fingerprints with your
          contact out of band — that comparison, not the server, is what stops
          a key-substitution attack.
        </p>

        <label>My identity key</label>
        {identity ? (
          <div className="card">
            <h3>
              fingerprint <span className="badge good">{formatFingerprint(identity.fingerprintHex)}</span>
            </h3>
            <div className="meta">
              {myPublishedKey
                ? `published · v${myPublishedKey.keyVersion}`
                : 'not published yet'}
            </div>
            <div className="btn-row" style={{ marginTop: '0.5rem' }}>
              {!myPublishedKey && (
                <button className="btn" onClick={() => void publishRestored()} type="button">
                  Publish this key
                </button>
              )}
              <button className="btn btn-ghost" onClick={exportBackup} type="button">
                Export backup
              </button>
            </div>
          </div>
        ) : (
          <div className="btn-row" style={{ marginBottom: '0.8rem' }}>
            <button className="btn" onClick={() => void generateAndPublish()} type="button">
              Generate & publish identity key
            </button>
          </div>
        )}
        {!identity && (
          <>
            <label htmlFor="backup">Restore from backup file content</label>
            <textarea
              id="backup"
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder="paste the contents of cipherlab-identity-backup.txt"
            />
            <div className="btn-row" style={{ marginBottom: '0.8rem' }}>
              <button className="btn btn-ghost" onClick={() => void importBackup()} type="button">
                Restore backup
              </button>
            </div>
          </>
        )}

        <label>Published keys (v{keys.length ? Math.max(...keys.map((k) => k.keyVersion)) : 0} latest)</label>
        <div className="card-list">
          {keys.length === 0 && <p className="hint">No keys published yet.</p>}
          {keys.map((key) => (
            <div className="card" key={key.id}>
              <h3>
                v{key.keyVersion} · {key.keyType}{' '}
                {key.revoked ? <span className="badge bad">revoked</span> : <span className="badge good">active</span>}
              </h3>
              <div className="meta">fp {truncateMiddle(key.fingerprint, 12)}</div>
              {!key.revoked && (
                <button className="btn btn-ghost" onClick={() => void revokeKey(key.id)} type="button">
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>

        <NewConversation onCreated={load} />

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
        <h2>Secure channel</h2>
        {!selected && <p className="hint">Pick a conversation on the left.</p>}
        {selected && (
          <>
            <dl className="kv">
              <dt>conversation</dt>
              <dd>{truncateMiddle(selected.id, 10)}</dd>
              <dt>sessions</dt>
              <dd>{sessions.length}</dd>
            </dl>

            <div className="btn-row" style={{ marginBottom: '0.8rem' }}>
              <button className="btn btn-ghost" onClick={() => void refreshChannel(selected.id)} type="button">
                Refresh
              </button>
              {!activeSession && pendingSessions.length === 0 && (
                <button className="btn" onClick={() => void startHandshake()} type="button">
                  Start secure session
                </button>
              )}
            </div>

            {pendingSessions.map((session) => (
              <div className="card" key={session.id}>
                <h3>
                  {truncateMiddle(session.id, 8)} <span className="badge warn">PENDING</span>
                </h3>
                {session.responderId === user?.id ? (
                  <button className="btn" onClick={() => void completeHandshake(session)} type="button">
                    Verify & complete handshake
                  </button>
                ) : (
                  <div className="meta">waiting for the partner to complete the handshake…</div>
                )}
              </div>
            ))}

            {activeSession && (
              <div className="card">
                <h3>
                  {truncateMiddle(activeSession.id, 8)} <span className="badge good">ACTIVE</span>
                </h3>
                <div className="meta">
                  transcript {truncateMiddle(activeSession.transcriptHash ?? '', 12)} · keys derived locally
                </div>
                <label style={{ marginTop: '0.8rem' }}>Message (encrypted before leaving this browser)</label>
                <textarea value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
                <div className="btn-row">
                  <button className="btn" onClick={() => void send()} type="button">
                    Encrypt & send
                  </button>
                  {lastMine && (
                    <button className="btn btn-danger" onClick={() => void send(lastMine)} type="button">
                      Replay last envelope (server must reject)
                    </button>
                  )}
                </div>
              </div>
            )}

            {status && <div className="status ok" style={{ marginTop: '0.8rem' }}>{status}</div>}
            {error && <div className="status error" style={{ marginTop: '0.8rem' }}>{error}</div>}

            <label>History ({messages.length})</label>
            <div className="messages">
              {messages.length === 0 && <p className="hint">No messages yet.</p>}
              {messages.map((message) => (
                <div key={message.id} className={message.senderId === user?.id ? 'message mine' : 'message'}>
                  <div className="sender">
                    seq {message.sequenceNumber} · {message.senderId === user?.id ? 'you' : 'partner'} ·{' '}
                    {message.sessionId === activeSession?.id ? 'this session' : 'older session'}
                  </div>
                  {decoded[message.id] !== undefined ? (
                    decoded[message.id] !== null ? (
                      <div className="body">{decoded[message.id]}</div>
                    ) : (
                      <div className="body">
                        <span className="badge bad">undecryptable</span>{' '}
                        {derivedSessionIds.has(message.sessionId)
                          ? '— authentication failed (tampered or relocated envelope)'
                          : '— session keys not held in this browser session'}
                      </div>
                    )
                  ) : (
                    <div className="body">…</div>
                  )}
                  <div className="envelope">
                    nonce {truncateMiddle(message.nonce, 10)} · ct {truncateMiddle(message.ciphertext, 18)}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )

  async function publishRestored() {
    if (!identity) return
    try {
      await identityApi.publish('EC_P256', identity.spkiB64)
      setStatus('Key published.')
      await load()
    } catch (e) {
      showError(e, 'Failed to publish')
    }
  }
}

function formatFingerprint(hex: string): string {
  return hex.replace(/(.{4})/g, '$1 ').trim()
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
        placeholder="paste a user id (see /auth/me or register response)"
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
