/**
 * End-to-end encryption for the Secure Messenger — real Web Crypto, no
 * server involvement beyond relaying opaque envelopes.
 *
 * Protocol (mirrors backend SessionTranscript byte-for-byte):
 *
 *   1. Each user has an ECDSA P-256 IDENTITY keypair generated here in the
 *      browser. Only the SPKI public half is ever uploaded; the private half
 *      lives in component memory (optionally exported to a user-held file —
 *      never localStorage, never the server, never logs).
 *   2. Handshake: initiator signs `cipherlab-session-v1|sid|conv|init|resp|suite|A:ephA`
 *      with its identity key; the responder verifies that against the
 *      initiator's PUBLISHED key, then signs the full transcript (+"|B:ephB").
 *      The initiator verifies it the same way. Signatures travel DER-encoded
 *      (JCA wire format); Web Crypto's raw r||s is wrapped/unwrapped here.
 *   3. Keys: HKDF-SHA-256 over ECDH(ephA, ephB), salted with the session id,
 *      with TWO context-separated info labels (a2b / b2a) → two directional
 *      AES-256-GCM keys. Nothing derived ever leaves browser memory.
 *   4. Messages: fresh random 96-bit nonce per encryption; AAD binds
 *      sessionId|conversationId|senderId|sequenceNumber, so an envelope
 *      cannot be moved to another session, conversation, sender or position
 *      without failing authentication.
 */

export const SUITE = 'EC_P256+HKDF-SHA256+AES-256-GCM'
const TRANSCRIPT_PREFIX = 'cipherlab-session-v1'

export interface HandshakeMeta {
  sessionId: string
  conversationId: string
  initiatorId: string
  responderId: string
}

export interface IdentityKeyPair {
  privateKey: CryptoKey
  spkiB64: string
  fingerprintHex: string
  /** Backup string for the user's own file: `<pkcs8-base64>:<spki-base64>`. */
  backup: string
}

export interface EphemeralKeyPair {
  privateKey: CryptoKey
  spkiB64: string
}

export interface SessionKeys {
  sendKey: CryptoKey
  receiveKey: CryptoKey
}

export interface MessageMeta {
  sessionId: string
  conversationId: string
  senderId: string
  sequenceNumber: number
}

const subtle = () => crypto.subtle

// ---------------------------------------------------------------- base64

export function toB64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function fromB64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// ---------------------------------------------------------------- identity keys

/** Generates the user's long-term identity keypair. Private half never leaves the browser. */
export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  const pair = (await subtle().generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable: needed to export the private half for the user's own backup file
    ['sign', 'verify'],
  )) as CryptoKeyPair
  return exportIdentity(pair)
}

/**
 * Restores an identity keypair from the user's own backup string
 * (`<pkcs8>:<spki>`). Web Crypto cannot re-derive the public half from a
 * PKCS#8 import, so the export file carries both halves — still private
 * material under the user's control; it never touches the server.
 */
export async function importIdentityPrivateKey(backup: string): Promise<IdentityKeyPair> {
  const [pkcs8B64, spkiB64] = backup.trim().split(':')
  if (!pkcs8B64 || !spkiB64) {
    throw new Error('Backup must be "<pkcs8>:<spki>" — re-export it from this app.')
  }
  const privateKey = await subtle().importKey(
    'pkcs8',
    fromB64(pkcs8B64) as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )
  const spki = fromB64(spkiB64)
  return {
    privateKey,
    spkiB64,
    fingerprintHex: await sha256Hex(spki),
    backup: `${pkcs8B64}:${spkiB64}`,
  }
}

async function exportIdentity(pair: CryptoKeyPair): Promise<IdentityKeyPair> {
  const spki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey))
  const pkcs8 = toB64(new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey)))
  const spkiB64 = toB64(spki)
  return {
    privateKey: pair.privateKey,
    spkiB64,
    fingerprintHex: await sha256Hex(spki),
    backup: `${pkcs8}:${spkiB64}`,
  }
}

/** SHA-256 of the SPKI bytes, lowercase hex — identical to the server's fingerprint. */
export async function fingerprintOfSpki(spkiB64: string): Promise<string> {
  return sha256Hex(fromB64(spkiB64))
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await subtle().digest('SHA-256', bytes as BufferSource))
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function importPublicSpki(spkiB64: string): Promise<CryptoKey> {
  return subtle().importKey(
    'spki',
    fromB64(spkiB64) as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  )
}

// ---------------------------------------------------------------- transcripts

/** What the initiator signs (must match backend SessionTranscript.initiatorForm). */
export function initiatorTranscript(meta: HandshakeMeta, ephA: string): string {
  return (
    `${TRANSCRIPT_PREFIX}|${meta.sessionId}|${meta.conversationId}|${meta.initiatorId}` +
    `|${meta.responderId}|${SUITE}|A:${ephA}`
  )
}

/** What both sides derive keys from (must match backend SessionTranscript.fullForm). */
export function fullTranscript(meta: HandshakeMeta, ephA: string, ephB: string): string {
  return `${initiatorTranscript(meta, ephA)}|B:${ephB}`
}

// ---------------------------------------------------------------- signatures (DER on the wire)

export async function signTranscript(privateKey: CryptoKey, transcript: string): Promise<string> {
  const raw = new Uint8Array(
    await subtle().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      new TextEncoder().encode(transcript),
    ),
  )
  return toB64(rawToDer(raw))
}

/** Verifies a peer's DER signature over the transcript against its published identity key. */
export async function verifyTranscript(
  identitySpkiB64: string,
  transcript: string,
  signatureB64: string,
): Promise<boolean> {
  try {
    const publicKey = await importPublicSpki(identitySpkiB64)
    return await subtle().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      derToRaw(fromB64(signatureB64)) as BufferSource,
      new TextEncoder().encode(transcript),
    )
  } catch {
    return false // malformed key or signature: fail closed, never throw
  }
}

/** Web Crypto emits raw r||s (64 bytes); JCA verifies DER. Wrap for the wire. */
export function rawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error('ECDSA raw signature must be 64 bytes')
  const r = integerDer(raw.subarray(0, 32))
  const s = integerDer(raw.subarray(32, 64))
  const body = concat(r, s)
  return concat(Uint8Array.of(0x30, body.length), body)
}

function integerDer(x: Uint8Array): Uint8Array {
  let start = 0
  while (start < x.length - 1 && x[start] === 0) start += 1
  let value = x.subarray(start)
  if (value[0] & 0x80) value = concat(Uint8Array.of(0), value)
  return concat(Uint8Array.of(0x02, value.length), value)
}

/** Parse a DER ECDSA signature back to raw r||s for Web Crypto verification. */
export function derToRaw(der: Uint8Array): Uint8Array {
  let offset = 0
  const readByte = () => {
    if (offset >= der.length) throw new Error('malformed DER signature')
    return der[offset++]
  }
  if (readByte() !== 0x30) throw new Error('malformed DER signature')
  let length = readByte()
  if (length & 0x80) {
    const count = length & 0x7f
    length = 0
    for (let i = 0; i < count; i += 1) length = (length << 8) | readByte()
  }
  const end = offset + length
  const readInteger = () => {
    if (readByte() !== 0x02) throw new Error('malformed DER signature')
    const size = readByte()
    const value = der.subarray(offset, offset + size)
    offset += size
    return value
  }
  const r = readInteger()
  const s = readInteger()
  if (offset !== end) throw new Error('malformed DER signature')
  return concat(pad32(r), pad32(s))
}

function pad32(value: Uint8Array): Uint8Array {
  let start = 0
  while (start < value.length - 1 && value[start] === 0) start += 1
  const trimmed = value.subarray(start)
  if (trimmed.length > 32) throw new Error('integer out of range for P-256')
  const out = new Uint8Array(32)
  out.set(trimmed, 32 - trimmed.length)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

// ---------------------------------------------------------------- handshake keys

export async function generateEphemeralKeyPair(): Promise<EphemeralKeyPair> {
  const pair = (await subtle().generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  )) as CryptoKeyPair
  const spki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey))
  return { privateKey: pair.privateKey, spkiB64: toB64(spki) }
}

async function importEphemeralPublic(spkiB64: string): Promise<CryptoKey> {
  return subtle().importKey(
    'spki',
    fromB64(spkiB64) as BufferSource,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  )
}

/**
 * Derives the two directional AES-256-GCM keys for an active session.
 * `amInitiator` decides which direction is send vs receive; the two info
 * labels guarantee the keys are cryptographically unrelated, so Alice can
 * never forge a message that decrypts as if Bob sent it (and vice versa).
 */
export async function deriveSessionKeys(
  meta: HandshakeMeta,
  ephA: string,
  ephB: string,
  myEphemeralPrivate: CryptoKey,
  amInitiator: boolean,
): Promise<SessionKeys> {
  const transcript = fullTranscript(meta, ephA, ephB)
  const sharedBits = new Uint8Array(
    await subtle().deriveBits(
      { name: 'ECDH', public: await importEphemeralPublic(amInitiator ? ephB : ephA) },
      myEphemeralPrivate,
      256,
    ),
  )
  const salt = uuidBytes(meta.sessionId)
  const a2b = await hkdfAesKey(sharedBits, salt, `${transcript}|a2b`)
  const b2a = await hkdfAesKey(sharedBits, salt, `${transcript}|b2a`)
  return amInitiator
    ? { sendKey: a2b, receiveKey: b2a }
    : { sendKey: b2a, receiveKey: a2b }
}

async function hkdfAesKey(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: derived keys cannot leave the browser even via export
    ['encrypt', 'decrypt'],
  )
}

function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '')
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error('invalid session id')
  const out = new Uint8Array(16)
  for (let i = 0; i < 16; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

// ---------------------------------------------------------------- messages

/**
 * Encrypts one message. Fresh 96-bit nonce every call (never reused under a
 * given key — GCM's one unforgivable sin); AAD pins the envelope to this
 * session, conversation, sender and sequence number.
 */
export async function encryptMessage(
  sendKey: CryptoKey,
  meta: MessageMeta,
  plaintext: string,
): Promise<{ nonceB64: string; ciphertextB64: string }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad(meta) },
      sendKey,
      new TextEncoder().encode(plaintext),
    ),
  )
  return { nonceB64: toB64(nonce), ciphertextB64: toB64(ciphertext) }
}

/**
 * Decrypts one envelope. Throws on ANY authentication failure — tampered
 * ciphertext, wrong tag, or an envelope moved to a different session,
 * conversation, sender or sequence position (the AAD binds all four).
 */
export async function decryptMessage(
  receiveKey: CryptoKey,
  meta: MessageMeta,
  nonceB64: string,
  ciphertextB64: string,
): Promise<string> {
  const plain = await subtle().decrypt(
    { name: 'AES-GCM', iv: fromB64(nonceB64) as BufferSource, additionalData: aad(meta) },
    receiveKey,
    fromB64(ciphertextB64) as BufferSource,
  )
  return new TextDecoder().decode(plain)
}

function aad(meta: MessageMeta): BufferSource {
  const value = `${meta.sessionId}|${meta.conversationId}|${meta.senderId}|${meta.sequenceNumber}`
  return new TextEncoder().encode(value)
}
