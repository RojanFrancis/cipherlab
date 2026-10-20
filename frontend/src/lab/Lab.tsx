import { useState } from 'react'
import { lab } from '../lib/api'
import type {
  DiffieHellmanResponse,
  EncryptResponse,
  HkdfResponse,
  MitmResponse,
  SignatureKeygenResponse,
} from '../lib/api'
import { ApiError } from '../lib/api'
import { textToBase64, truncateMiddle } from '../lib/b64'

/**
 * The Crypto Lab: six experiments, each a thin wrapper over a backend
 * endpoint. The point of every panel is the same — make an invisible
 * property visible, then let you break it.
 */

type Experiment =
  | 'aes'
  | 'hashing'
  | 'dh'
  | 'hkdf'
  | 'signatures'
  | 'mitm'

const EXPERIMENTS: { id: Experiment; label: string }[] = [
  { id: 'aes', label: 'AES-GCM tamper' },
  { id: 'hashing', label: 'Hash & HMAC' },
  { id: 'dh', label: 'Diffie-Hellman' },
  { id: 'hkdf', label: 'HKDF derivation' },
  { id: 'signatures', label: 'Signatures' },
  { id: 'mitm', label: 'MITM attack' },
]

export function Lab() {
  const [active, setActive] = useState<Experiment>('aes')

  return (
    <div>
      <div className="lab-nav">
        {EXPERIMENTS.map((experiment) => (
          <button
            key={experiment.id}
            className={active === experiment.id ? 'active' : ''}
            onClick={() => setActive(experiment.id)}
            type="button"
          >
            {experiment.label}
          </button>
        ))}
      </div>

      {active === 'aes' && <AesPanel />}
      {active === 'hashing' && <HashingPanel />}
      {active === 'dh' && <DhPanel />}
      {active === 'hkdf' && <HkdfPanel />}
      {active === 'signatures' && <SignaturePanel />}
      {active === 'mitm' && <MitmPanel />}
    </div>
  )
}

/** Surface any API error in a consistent, non-technical way. */
function useErrorText() {
  const [error, setError] = useState<string | null>(null)
  const capture = (e: unknown) => {
    if (e instanceof ApiError) {
      setError(`${e.code}: ${e.message}`)
    } else if (e instanceof Error) {
      setError(e.message)
    } else {
      setError('Unexpected error')
    }
  }
  return { error, setError, capture }
}

// ---------------------------------------------------------------- AES

function AesPanel() {
  const [plaintext, setPlaintext] = useState('attack at dawn 🔐')
  const [result, setResult] = useState<EncryptResponse | null>(null)
  const [decrypted, setDecrypted] = useState<string | null>(null)
  const [tamperField, setTamperField] = useState<'none' | 'ciphertext' | 'tag' | 'key' | 'nonce'>('none')
  const { error, setError, capture } = useErrorText()

  const encrypt = async () => {
    setError(null)
    setDecrypted(null)
    try {
      setResult(await lab.encrypt(plaintext))
    } catch (e) {
      capture(e)
    }
  }

  const decrypt = async (tamper: typeof tamperField) => {
    if (!result) return
    setError(null)
    try {
      let key = result.key
      let nonce = result.nonce
      let ciphertext = result.ciphertext
      let tag = result.tag

      // Flip the first byte of the chosen field — one bit is enough.
      const flip = (value: string): string => {
        const bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0))
        bytes[0] ^= 0x01
        return btoa(String.fromCharCode(...bytes))
      }
      if (tamper === 'ciphertext') ciphertext = flip(ciphertext)
      if (tamper === 'tag') tag = flip(tag)
      if (tamper === 'key') key = flip(key)
      if (tamper === 'nonce') nonce = flip(nonce)

      const response = await lab.decrypt(key, nonce, ciphertext, tag)
      setDecrypted(response.authenticated
        ? `${response.plaintext}  (authenticated=true)`
        : `${response.plaintext}  (authenticated=false)`)
    } catch (e) {
      // A rejected ciphertext arrives as 400 INVALID_CIPHERTEXT — that IS
      // the lesson: GCM refuses to hand back plaintext it cannot trust.
      capture(e)
    }
  }

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>AES-256-GCM</h2>
        <p className="hint">
          Encrypt on the server, then decrypt with a deliberately corrupted field.
          GCM authenticates before it returns anything — a single flipped bit
          anywhere makes the whole thing fail closed.
        </p>
        <label htmlFor="aes-plain">Plaintext</label>
        <textarea id="aes-plain" value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
        <div className="btn-row">
          <button className="btn" onClick={encrypt} type="button">Encrypt</button>
        </div>

        {result && (
          <>
            <h2 style={{ marginTop: '1rem' }}>Try tampering</h2>
            <p className="hint">Corrupt one field, then decrypt and watch the tag reject it.</p>
            <label htmlFor="tamper">Field to corrupt</label>
            <select
              id="tamper"
              value={tamperField}
              onChange={(e) => setTamperField(e.target.value as typeof tamperField)}
            >
              <option value="none">none — decrypt honestly</option>
              <option value="ciphertext">flip a ciphertext bit</option>
              <option value="tag">flip a tag bit</option>
              <option value="key">flip a key bit</option>
              <option value="nonce">flip a nonce bit</option>
            </select>
            <div className="btn-row">
              <button className="btn" onClick={() => decrypt(tamperField)} type="button">
                Decrypt
              </button>
            </div>
          </>
        )}
      </div>

      <div className="panel">
        <h2>Output</h2>
        {!result && <p className="hint">Encrypt something to see the envelope.</p>}
        {result && (
          <>
            <dl className="kv">
              <dt>algorithm</dt><dd>{result.algorithm}</dd>
              <dt>key (32 B)</dt><dd>{truncateMiddle(result.key, 14)}</dd>
              <dt>nonce (12 B)</dt><dd>{truncateMiddle(result.nonce, 14)}</dd>
              <dt>ciphertext</dt><dd>{truncateMiddle(result.ciphertext, 16)}</dd>
              <dt>tag (16 B)</dt><dd>{truncateMiddle(result.tag, 14)}</dd>
              <dt>combined</dt><dd>{truncateMiddle(result.combined, 16)} <span className="badge">ciphertext‖tag</span></dd>
            </dl>
            <p className="note">{result.securityNote}</p>
          </>
        )}
        {error && <div className="status error">{error}</div>}
        {decrypted && <div className="status ok">{decrypted}</div>}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- hashing

function HashingPanel() {
  const [input, setInput] = useState('The quick brown fox')
  const [key, setKey] = useState('shared secret')
  const [digest, setDigest] = useState<string | null>(null)
  const [mac, setMac] = useState<string | null>(null)
  const { error, setError, capture } = useErrorText()

  const run = async (algorithm: 'SHA-256' | 'SHA-512') => {
    setError(null)
    try {
      const hash = await lab.hash(input, algorithm)
      setDigest(hash.digest)
      const hmac = await lab.hmac(key, input)
      setMac(hmac.mac)
    } catch (e) {
      capture(e)
    }
  }

  const avalanche = async () => {
    setError(null)
    try {
      const a = await lab.hash(input, 'SHA-256')
      const b = await lab.hash(`${input} `, 'SHA-256')
      const differing = countDifferingHexChars(a.digest, b.digest)
      setDigest(`${a.digest}\n\none character changed →\n${b.digest}\n\n${differing} of 64 hex chars differ (avalanche)`)
      setMac(null)
    } catch (e) {
      capture(e)
    }
  }

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>Hash vs HMAC</h2>
        <p className="hint">
          A hash commits to a message anyone can recompute. An HMAC proves
          <em> you</em> computed it, because only you hold the key — which is
          why a hash alone can never authenticate.
        </p>
        <label htmlFor="hash-input">Input</label>
        <textarea id="hash-input" value={input} onChange={(e) => setInput(e.target.value)} />
        <label htmlFor="hmac-key">HMAC key</label>
        <input id="hmac-key" value={key} onChange={(e) => setKey(e.target.value)} />
        <div className="btn-row">
          <button className="btn" onClick={() => run('SHA-256')} type="button">SHA-256</button>
          <button className="btn" onClick={() => run('SHA-512')} type="button">SHA-512</button>
          <button className="btn btn-ghost" onClick={avalanche} type="button">
            Avalanche demo
          </button>
        </div>
        {error && <div className="status error" style={{ marginTop: '0.7rem' }}>{error}</div>}
      </div>

      <div className="panel">
        <h2>Output</h2>
        {digest && (
          <>
            <label>Digest</label>
            <div className="output">{digest}</div>
          </>
        )}
        {mac && (
          <>
            <label>HMAC-SHA-256</label>
            <div className="output">{mac}</div>
            <p className="note">
              Same input, different construction: without the key, an attacker
              can recompute the digest but not this MAC.
            </p>
          </>
        )}
        {!digest && !mac && <p className="hint">Run a hash to see output.</p>}
      </div>
    </div>
  )
}

function countDifferingHexChars(a: string, b: string): number {
  let differing = 0
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) differing += 1
  }
  return differing
}

// ---------------------------------------------------------------- DH

function DhPanel() {
  const [p, setP] = useState('23')
  const [g, setG] = useState('5')
  const [alicePrivate, setAlicePrivate] = useState('6')
  const [bobPrivate, setBobPrivate] = useState('15')
  const [result, setResult] = useState<DiffieHellmanResponse | null>(null)
  const { error, setError, capture } = useErrorText()

  const run = async () => {
    setError(null)
    try {
      setResult(await lab.diffieHellman(p, g, alicePrivate, bobPrivate))
    } catch (e) {
      capture(e)
    }
  }

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>Textbook Diffie-Hellman</h2>
        <p className="hint">
          Two strangers arrive at the same secret over a public channel. Try
          p=23, g=5, a=6, b=15 → both sides land on 2. Now change one private
          value and watch only the other side move.
        </p>
        <div className="grid-2">
          <div>
            <label htmlFor="dh-p">prime p</label>
            <input id="dh-p" value={p} onChange={(e) => setP(e.target.value)} />
            <label htmlFor="dh-g">base g</label>
            <input id="dh-g" value={g} onChange={(e) => setG(e.target.value)} />
          </div>
          <div>
            <label htmlFor="dh-a">alice private a</label>
            <input id="dh-a" value={alicePrivate} onChange={(e) => setAlicePrivate(e.target.value)} />
            <label htmlFor="dh-b">bob private b</label>
            <input id="dh-b" value={bobPrivate} onChange={(e) => setBobPrivate(e.target.value)} />
          </div>
        </div>
        <button className="btn" onClick={run} type="button">Compute</button>
        {error && <div className="status error" style={{ marginTop: '0.7rem' }}>{error}</div>}
      </div>

      <div className="panel">
        <h2>Exchange</h2>
        {!result && <p className="hint">Compute to see the exchange.</p>}
        {result && (
          <>
            <dl className="kv">
              <dt>A = g^a mod p</dt><dd>{result.alicePublic}</dd>
              <dt>B = g^b mod p</dt><dd>{result.bobPublic}</dd>
              <dt>A^b mod p</dt><dd>{result.sharedSecret}</dd>
              <dt>B^a mod p</dt><dd>{result.sharedSecret}</dd>
            </dl>
            <label>Steps</label>
            <ol className="steps">
              {result.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
            <p className="note">{result.securityNote}</p>
          </>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- HKDF

function HkdfPanel() {
  const [ikm, setIkm] = useState(textToBase64('input key material'))
  const [salt, setSalt] = useState(textToBase64('random salt'))
  const [info, setInfo] = useState('app v1 / encryption key')
  const [length, setLength] = useState(32)
  const [result, setResult] = useState<HkdfResponse | null>(null)
  const { error, setError, capture } = useErrorText()

  const run = async () => {
    setError(null)
    try {
      setResult(await lab.hkdf(ikm, salt, info, length))
    } catch (e) {
      capture(e)
    }
  }

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>HKDF-SHA-256</h2>
        <p className="hint">
          One shared secret becomes many independent keys. The{' '}
          <code>info</code> label binds each key to its purpose — change it and
          you get a completely different key, which is what stops
          key-reuse bugs.
        </p>
        <label htmlFor="hkdf-ikm">IKM (Base64)</label>
        <input id="hkdf-ikm" value={ikm} onChange={(e) => setIkm(e.target.value)} />
        <label htmlFor="hkdf-salt">Salt (Base64)</label>
        <input id="hkdf-salt" value={salt} onChange={(e) => setSalt(e.target.value)} />
        <label htmlFor="hkdf-info">Info label</label>
        <input id="hkdf-info" value={info} onChange={(e) => setInfo(e.target.value)} />
        <label htmlFor="hkdf-len">Output length (bytes)</label>
        <input
          id="hkdf-len"
          type="number"
          min={1}
          max={8160}
          value={length}
          onChange={(e) => setLength(Number(e.target.value))}
        />
        <button className="btn" onClick={run} type="button">Derive</button>
        {error && <div className="status error" style={{ marginTop: '0.7rem' }}>{error}</div>}
      </div>

      <div className="panel">
        <h2>Derivation</h2>
        {!result && <p className="hint">Derive to see the two-stage process.</p>}
        {result && (
          <>
            <label>PRK = HMAC(salt, IKM)</label>
            <div className="output">{result.prkHex}</div>
            <label>OKM = Expand(PRK, info, L)</label>
            <div className="output">{result.outputHex}</div>
            <label>Steps</label>
            <ol className="steps">
              {result.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
            <p className="note">{result.securityNote}</p>
          </>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- signatures

function SignaturePanel() {
  const [keys, setKeys] = useState<SignatureKeygenResponse | null>(null)
  const [message, setMessage] = useState('transfer $100 to alice')
  const [signature, setSignature] = useState<string | null>(null)
  const [verification, setVerification] = useState<string | null>(null)
  const { error, setError, capture } = useErrorText()

  const generate = async () => {
    setError(null)
    setSignature(null)
    setVerification(null)
    try {
      setKeys(await lab.keygen())
    } catch (e) {
      capture(e)
    }
  }

  const sign = async () => {
    if (!keys) return
    setError(null)
    try {
      const response = await lab.sign(message, keys.privateKey)
      setSignature(response.signature)
      setVerification(null)
    } catch (e) {
      capture(e)
    }
  }

  const verify = async (tamper: boolean) => {
    if (!keys || !signature) return
    setError(null)
    try {
      // A one-character change to the message: the signature must die.
      const subject = tamper ? `${message} ` : message
      const response = await lab.verify(subject, signature, keys.publicKey)
      setVerification(response.explanation)
    } catch (e) {
      capture(e)
    }
  }

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>ECDSA P-256</h2>
        <p className="hint">
          Sign a message with a private key; anyone with the public key can
          verify. Then change one character of the message — verification
          fails, which is exactly what "integrity with origin" means.
        </p>
        {!keys && <p className="hint">Generate a keypair to begin.</p>}
        {keys && (
          <>
            <dl className="kv">
              <dt>algorithm</dt><dd>{keys.algorithm}</dd>
              <dt>private</dt><dd>{truncateMiddle(keys.privateKey, 12)}</dd>
              <dt>public</dt><dd>{truncateMiddle(keys.publicKey, 12)}</dd>
              <dt>fingerprint</dt><dd>{keys.fingerprint}</dd>
            </dl>
            <p className="note">{keys.securityNote}</p>
          </>
        )}
        <label htmlFor="sig-msg">Message</label>
        <textarea id="sig-msg" value={message} onChange={(e) => setMessage(e.target.value)} />
        <div className="btn-row">
          <button className="btn btn-ghost" onClick={generate} type="button">
            {keys ? 'New keypair' : 'Generate keypair'}
          </button>
          <button className="btn" onClick={sign} disabled={!keys} type="button">Sign</button>
        </div>
        {error && <div className="status error" style={{ marginTop: '0.7rem' }}>{error}</div>}
      </div>

      <div className="panel">
        <h2>Verification</h2>
        {!signature && <p className="hint">Sign a message to produce a signature.</p>}
        {signature && (
          <>
            <label>Signature</label>
            <div className="output">{truncateMiddle(signature, 24)}</div>
            <div className="btn-row">
              <button className="btn" onClick={() => verify(false)} type="button">
                Verify original
              </button>
              <button className="btn btn-danger" onClick={() => verify(true)} type="button">
                Verify tampered
              </button>
            </div>
          </>
        )}
        {verification && <div className="status info" style={{ marginTop: '0.7rem' }}>{verification}</div>}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- MITM

function MitmPanel() {
  const [result, setResult] = useState<MitmResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const { error, setError, capture } = useErrorText()

  const run = async (mode: 'unauthenticated' | 'authenticated') => {
    setError(null)
    setLoading(true)
    try {
      setResult(await lab.mitm(mode))
    } catch (e) {
      capture(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid-2">
      <div className="panel">
        <h2>Man-in-the-Middle</h2>
        <p className="hint">
          The same attack, twice. Without authentication Mallory reads
          everything and nobody notices. With signatures bound to identities,
          the substitution is caught before a session key ever exists.
        </p>
        <div className="btn-row">
          <button className="btn btn-danger" onClick={() => run('unauthenticated')} disabled={loading} type="button">
            Unauthenticated attack
          </button>
          <button className="btn" onClick={() => run('authenticated')} disabled={loading} type="button">
            With signatures
          </button>
        </div>
        {error && <div className="status error" style={{ marginTop: '0.7rem' }}>{error}</div>}
        {result && (
          <>
            <div
              className={`status ${result.malloryCanRead ? 'error' : 'ok'}`}
              style={{ marginTop: '0.9rem' }}
            >
              {result.malloryCanRead
                ? 'Mallory can read everything — attack succeeded'
                : 'Mallory reads nothing — substitution rejected'}
            </div>
            <label>Participants</label>
            <div className="output">{result.participants.join(', ')}</div>
            <label>Shared secrets</label>
            <dl className="kv">
              {Object.entries(result.sharedSecrets).map(([who, secret]) => (
                <div key={who} style={{ display: 'contents' }}>
                  <dt>{who}</dt>
                  <dd>{secret}</dd>
                </div>
              ))}
            </dl>
            <p className="note">{result.securityNote}</p>
          </>
        )}
      </div>

      <div className="panel">
        <h2>Narrative</h2>
        {!result && <p className="hint">Run an attack to see what happened, step by step.</p>}
        {result && (
          <ol className="steps">
            {result.steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        )}
      </div>
    </div>
  )
}
