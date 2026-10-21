/**
 * Proves the messaging crypto layer behaves as the protocol promises.
 * Runs on Node's Web Crypto (same API the browser provides).
 */
import { describe, expect, it } from 'vitest'
import {
  decryptMessage,
  derToRaw,
  encryptMessage,
  fullTranscript,
  generateEphemeralKeyPair,
  generateIdentityKeyPair,
  importIdentityPrivateKey,
  initiatorTranscript,
  rawToDer,
  signTranscript,
  verifyTranscript,
  deriveSessionKeys,
  establishInitiatorSession,
  fingerprintOfSpki,
  fromB64,
  toB64,
  SUITE,
} from './e2ee'
import type { HandshakeMeta, InitiatorExpectation, InitiatorSessionResult, MessageMeta } from './e2ee'
import type { CryptoSession, IdentityKey } from './api'

const META: HandshakeMeta = {
  sessionId: '11111111-2222-4333-8444-555555555555',
  conversationId: '99999999-8888-4777-8666-555555555555',
  initiatorId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  responderId: 'ffffffff-0000-4111-8222-333333333333',
}

const otherMeta: HandshakeMeta = {
  ...META,
  sessionId: '11111111-2222-4333-8444-666666666666',
}

async function handshake(meta: HandshakeMeta) {
  const alice = await generateIdentityKeyPair()
  const bob = await generateIdentityKeyPair()
  const ephA = await generateEphemeralKeyPair()
  const ephB = await generateEphemeralKeyPair()
  const initiatorSig = await signTranscript(alice.privateKey, initiatorTranscript(meta, ephA.spkiB64))
  const responderSig = await signTranscript(bob.privateKey, fullTranscript(meta, ephA.spkiB64, ephB.spkiB64))
  const aliceKeys = await deriveSessionKeys(meta, ephA.spkiB64, ephB.spkiB64, ephA.privateKey, true)
  const bobKeys = await deriveSessionKeys(meta, ephA.spkiB64, ephB.spkiB64, ephB.privateKey, false)
  return { alice, bob, ephA, ephB, initiatorSig, responderSig, aliceKeys, bobKeys }
}

describe('identity keys', () => {
  it('fingerprints are the SHA-256 hex of the SPKI bytes', async () => {
    const identity = await generateIdentityKeyPair()
    const spki = fromB64(identity.spkiB64)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', spki as BufferSource))
    const expected = Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')
    expect(identity.fingerprintHex).toBe(expected)
    expect(identity.fingerprintHex).toMatch(/^[0-9a-f]{64}$/)
    expect(await fingerprintOfSpki(identity.spkiB64)).toBe(identity.fingerprintHex)
  })

  it('backup export → import restores an interchangeable signing key', async () => {
    const original = await generateIdentityKeyPair()
    const restored = await importIdentityPrivateKey(original.backup)
    expect(restored.spkiB64).toBe(original.spkiB64)
    expect(restored.fingerprintHex).toBe(original.fingerprintHex)

    const transcript = initiatorTranscript(META, 'ephA-example')
    const signature = await signTranscript(restored.privateKey, transcript)
    expect(await verifyTranscript(restored.spkiB64, transcript, signature)).toBe(true)
  })

  it('rejects malformed backup strings', async () => {
    await expect(importIdentityPrivateKey('not-a-backup')).rejects.toThrow()
  })
})

describe('transcript signatures', () => {
  it('both sides verify each other; tampering with any field breaks it', async () => {
    const h = await handshake(META)
    const initiatorForm = initiatorTranscript(META, h.ephA.spkiB64)
    const fullForm = fullTranscript(META, h.ephA.spkiB64, h.ephB.spkiB64)

    expect(await verifyTranscript(h.alice.spkiB64, initiatorForm, h.initiatorSig)).toBe(true)
    expect(await verifyTranscript(h.bob.spkiB64, fullForm, h.responderSig)).toBe(true)

    // Tampered transcript (substituted ephemeral — the classic MITM move):
    const substituted = initiatorTranscript(META, (await generateEphemeralKeyPair()).spkiB64)
    expect(await verifyTranscript(h.alice.spkiB64, substituted, h.initiatorSig)).toBe(false)

    // Signature from a key that was not the registered one:
    const mallory = await generateIdentityKeyPair()
    expect(await verifyTranscript(mallory.spkiB64, initiatorForm, h.initiatorSig)).toBe(false)

    // Malformed signature: fails closed, never throws.
    expect(await verifyTranscript(h.alice.spkiB64, initiatorForm, '!!!not-base64!!!')).toBe(false)
    expect(await verifyTranscript(h.alice.spkiB64, initiatorForm, toB64(new Uint8Array(32)))).toBe(false)
  })

  it('DER and raw signature formats round-trip', async () => {
    const identity = await generateIdentityKeyPair()
    const signature = await signTranscript(identity.privateKey, 'a transcript')
    const der = fromB64(signature)
    expect(der[0]).toBe(0x30) // DER SEQUENCE
    const raw = derToRaw(der)
    expect(raw.length).toBe(64)
    expect(toB64(rawToDer(raw))).toBe(toB64(der))
    expect(() => derToRaw(new Uint8Array([1, 2, 3]))).toThrow()
  })
})

describe('directional session keys', () => {
  it("Alice's send key is Bob's receive key, and the reverse", async () => {
    const h = await handshake(META)
    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 0,
    }
    const fromAlice = await encryptMessage(h.aliceKeys.sendKey, meta, 'hello Bob')
    expect(await decryptMessage(h.bobKeys.receiveKey, meta, fromAlice.nonceB64, fromAlice.ciphertextB64))
      .toBe('hello Bob')

    const fromBob: MessageMeta = { ...meta, senderId: META.responderId }
    const envelope = await encryptMessage(h.bobKeys.sendKey, fromBob, 'hi Alice')
    expect(await decryptMessage(h.aliceKeys.receiveKey, fromBob, envelope.nonceB64, envelope.ciphertextB64))
      .toBe('hi Alice')
  })

  it('directional keys are cryptographically distinct — no cross-direction forgery', async () => {
    const h = await handshake(META)
    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 0,
    }
    const envelope = await encryptMessage(h.aliceKeys.sendKey, meta, 'from alice')
    // Bob's RECEIVE key decrypts it; Bob's SEND key must not (different direction).
    await expect(
      decryptMessage(h.bobKeys.sendKey, meta, envelope.nonceB64, envelope.ciphertextB64),
    ).rejects.toThrow()
  })

  it('HKDF context separation: a different session transcript yields unrelated keys', async () => {
    const h = await handshake(META)
    const otherEphA = await generateEphemeralKeyPair()
    const otherEphB = await generateEphemeralKeyPair()
    const otherKeys = await deriveSessionKeys(otherMeta, otherEphA.spkiB64, otherEphB.spkiB64,
      otherEphA.privateKey, true)

    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 0,
    }
    const envelope = await encryptMessage(h.aliceKeys.sendKey, meta, 'session one traffic')
    await expect(
      decryptMessage(otherKeys.receiveKey, meta, envelope.nonceB64, envelope.ciphertextB64),
    ).rejects.toThrow()
  })
})

describe('message authentication', () => {
  it('roundtrips unicode plaintext with a fresh nonce each time', async () => {
    const h = await handshake(META)
    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 3,
    }
    const first = await encryptMessage(h.aliceKeys.sendKey, meta, 'secret 🤫 メッセージ')
    const second = await encryptMessage(h.aliceKeys.sendKey, meta, 'secret 🤫 メッセージ')
    expect(first.nonceB64).not.toBe(second.nonceB64)
    expect(first.ciphertextB64).not.toBe(second.ciphertextB64)
    expect(await decryptMessage(h.bobKeys.receiveKey, meta, first.nonceB64, first.ciphertextB64))
      .toBe('secret 🤫 メッセージ')
  })

  it('rejects tampered ciphertext and tampered nonce', async () => {
    const h = await handshake(META)
    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 0,
    }
    const envelope = await encryptMessage(h.aliceKeys.sendKey, meta, 'pay me 100 coins')

    const bytes = fromB64(envelope.ciphertextB64)
    bytes[0] ^= 0x01 // flip one bit of ciphertext
    await expect(
      decryptMessage(h.bobKeys.receiveKey, meta, envelope.nonceB64, toB64(bytes)),
    ).rejects.toThrow()

    const nonce = fromB64(envelope.nonceB64)
    nonce[0] ^= 0x01
    await expect(
      decryptMessage(h.bobKeys.receiveKey, meta, toB64(nonce), envelope.ciphertextB64),
    ).rejects.toThrow()
  })

  it('AAD binds session, conversation, sender and sequence — relocation is detected', async () => {
    const h = await handshake(META)
    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 5,
    }
    const envelope = await encryptMessage(h.aliceKeys.sendKey, meta, 'bound message')

    // Same bytes, claimed as sequence 6:
    await expect(
      decryptMessage(h.bobKeys.receiveKey, { ...meta, sequenceNumber: 6 }, envelope.nonceB64, envelope.ciphertextB64),
    ).rejects.toThrow()
    // Claimed from Bob instead of Alice:
    await expect(
      decryptMessage(h.bobKeys.receiveKey, { ...meta, senderId: META.responderId }, envelope.nonceB64, envelope.ciphertextB64),
    ).rejects.toThrow()
    // Claimed in another conversation:
    await expect(
      decryptMessage(h.bobKeys.receiveKey, { ...meta, conversationId: '00000000-0000-4000-8000-000000000000' }, envelope.nonceB64, envelope.ciphertextB64),
    ).rejects.toThrow()
  })
})

// ---------------------------------------------------------------- initiator-side peer authentication
//
// Regression suite for the v1.1 review finding: the initiator used to take
// the server's ACTIVE flag at face value and derive keys without ever
// checking the responder's signature. Every case below must fail closed —
// `{ verified: false }` and NO key material — except the valid handshake.

async function initiatorFixture() {
  const alice = await generateIdentityKeyPair() // initiator
  const bob = await generateIdentityKeyPair() // responder
  const ephA = await generateEphemeralKeyPair()
  const ephB = await generateEphemeralKeyPair()
  const initiatorSignature = await signTranscript(alice.privateKey, initiatorTranscript(META, ephA.spkiB64))
  const responderSignature = await signTranscript(
    bob.privateKey,
    fullTranscript(META, ephA.spkiB64, ephB.spkiB64),
  )
  const session: CryptoSession = {
    id: META.sessionId,
    conversationId: META.conversationId,
    initiatorId: META.initiatorId,
    responderId: META.responderId,
    suite: SUITE,
    status: 'ACTIVE',
    createdAt: '2026-01-01T00:00:00',
    expiresAt: null,
    initiatorEphemeralPublic: ephA.spkiB64,
    initiatorSignature,
    initiatorIdentityKeyId: 'key-alice',
    responderEphemeralPublic: ephB.spkiB64,
    responderSignature,
    responderIdentityKeyId: 'key-bob',
    transcriptHash: null,
  }
  const responderKeys: IdentityKey[] = [
    {
      id: 'key-bob',
      userId: META.responderId,
      keyType: 'EC_P256',
      publicKey: bob.spkiB64,
      fingerprint: bob.fingerprintHex,
      keyVersion: 1,
      createdAt: '2026-01-01T00:00:00',
      revoked: false,
      revokedAt: null,
    },
  ]
  const expected: InitiatorExpectation = {
    meta: META,
    suite: SUITE,
    initiatorEphemeralPublic: ephA.spkiB64,
    initiatorIdentityKeyId: 'key-alice',
    initiatorIdentityPublicKey: alice.spkiB64,
  }
  return { bob, ephA, ephB, session, responderKeys, expected }
}

/** Asserts verification failed AND that no key material came back. */
function expectRejected(result: InitiatorSessionResult, pattern: RegExp): void {
  expect(result.verified).toBe(false)
  expect('keys' in result).toBe(false)
  if (result.verified) throw new Error(`expected rejection matching ${pattern}`)
  expect(result.reason).toMatch(pattern)
}

describe('initiator-side responder authentication', () => {
  it('accepts a valid two-user handshake and derives keys both sides agree on', async () => {
    const f = await initiatorFixture()
    const result = await establishInitiatorSession(f.expected, f.session, f.responderKeys, f.ephA.privateKey)
    expect(result.verified).toBe(true)
    if (!result.verified) throw new Error(result.reason)

    // The responder derives independently from the same transcript: the
    // initiator's send key must be the responder's receive key.
    const bobKeys = await deriveSessionKeys(META, f.ephA.spkiB64, f.ephB.spkiB64, f.ephB.privateKey, false)
    const meta: MessageMeta = {
      sessionId: META.sessionId,
      conversationId: META.conversationId,
      senderId: META.initiatorId,
      sequenceNumber: 0,
    }
    const envelope = await encryptMessage(result.keys.sendKey, meta, 'handshake verified')
    expect(await decryptMessage(bobKeys.receiveKey, meta, envelope.nonceB64, envelope.ciphertextB64)).toBe(
      'handshake verified',
    )
  })

  it('rejects an invalid responder signature', async () => {
    // (a) Signed by a key that is not the responder's published one.
    const a = await initiatorFixture()
    const mallory = await generateIdentityKeyPair()
    a.session.responderSignature = await signTranscript(
      mallory.privateKey,
      fullTranscript(META, a.ephA.spkiB64, a.ephB.spkiB64),
    )
    expectRejected(
      await establishInitiatorSession(a.expected, a.session, a.responderKeys, a.ephA.privateKey),
      /responder signature did NOT verify/,
    )

    // (b) A corrupted signature fails closed instead of throwing.
    const b = await initiatorFixture()
    const sig = b.session.responderSignature
    if (!sig) throw new Error('fixture missing responder signature')
    const bytes = fromB64(sig)
    bytes[bytes.length - 1] ^= 0x01
    b.session.responderSignature = toB64(bytes)
    expectRejected(
      await establishInitiatorSession(b.expected, b.session, b.responderKeys, b.ephA.privateKey),
      /responder signature did NOT verify/,
    )
  })

  it('rejects a substituted responder ephemeral key', async () => {
    const f = await initiatorFixture()
    const substituted = await generateEphemeralKeyPair()
    // The server swaps in ITS ephB; the real responder's signature was
    // made over the original one — verification must catch it.
    f.session.responderEphemeralPublic = substituted.spkiB64
    expectRejected(
      await establishInitiatorSession(f.expected, f.session, f.responderKeys, f.ephA.privateKey),
      /responder signature did NOT verify/,
    )
  })

  it('rejects incorrect responder identity-key references', async () => {
    // (a) The referenced key is not among the responder's published keys.
    const a = await initiatorFixture()
    a.session.responderIdentityKeyId = 'key-ghost'
    expectRejected(
      await establishInitiatorSession(a.expected, a.session, a.responderKeys, a.ephA.privateKey),
      /does not resolve/,
    )

    // (b) The referenced key belongs to a different user.
    const b = await initiatorFixture()
    b.responderKeys = [{ ...b.responderKeys[0], userId: META.initiatorId }]
    expectRejected(
      await establishInitiatorSession(b.expected, b.session, b.responderKeys, b.ephA.privateKey),
      /does not belong to the responder/,
    )
  })

  it('rejects an identity key that does not match its published fingerprint', async () => {
    const f = await initiatorFixture()
    f.responderKeys = [{ ...f.responderKeys[0], fingerprint: '0'.repeat(64) }]
    expectRejected(
      await establishInitiatorSession(f.expected, f.session, f.responderKeys, f.ephA.privateKey),
      /does not match its published fingerprint/,
    )
  })

  it('rejects a revoked responder identity key', async () => {
    const f = await initiatorFixture()
    f.responderKeys = [{ ...f.responderKeys[0], revoked: true }]
    expectRejected(
      await establishInitiatorSession(f.expected, f.session, f.responderKeys, f.ephA.privateKey),
      /revoked/,
    )
  })

  it('rejects a transcript the responder signed over different session context', async () => {
    const f = await initiatorFixture()
    const otherContext: HandshakeMeta = { ...META, sessionId: '11111111-2222-4333-8444-777777777777' }
    f.session.responderSignature = await signTranscript(
      f.bob.privateKey,
      fullTranscript(otherContext, f.ephA.spkiB64, f.ephB.spkiB64),
    )
    expectRejected(
      await establishInitiatorSession(f.expected, f.session, f.responderKeys, f.ephA.privateKey),
      /responder signature did NOT verify/,
    )
  })

  it('rejects session records that do not match the handshake this client created', async () => {
    // (a) A different conversation.
    const a = await initiatorFixture()
    a.session.conversationId = '99999999-8888-4777-8666-000000000000'
    expectRejected(
      await establishInitiatorSession(a.expected, a.session, a.responderKeys, a.ephA.privateKey),
      /different conversation/,
    )

    // (b) An initiator ephemeral that is not the one we generated.
    const b = await initiatorFixture()
    b.session.initiatorEphemeralPublic = (await generateEphemeralKeyPair()).spkiB64
    expectRejected(
      await establishInitiatorSession(b.expected, b.session, b.responderKeys, b.ephA.privateKey),
      /initiator ephemeral public key does not match/,
    )

    // (c) An identity-key reference to a key we did not sign with.
    const c = await initiatorFixture()
    c.session.initiatorIdentityKeyId = 'key-alice-old'
    expectRejected(
      await establishInitiatorSession(c.expected, c.session, c.responderKeys, c.ephA.privateKey),
      /initiator identity-key reference/,
    )

    // (d) A swapped suite (protocol context).
    const d = await initiatorFixture()
    d.session.suite = 'EC_P256+PLAINTEXT'
    expectRejected(
      await establishInitiatorSession(d.expected, d.session, d.responderKeys, d.ephA.privateKey),
      /suite/,
    )

    // (e) A session id that is not the one this client created.
    const e = await initiatorFixture()
    e.session.id = '11111111-2222-4333-8444-777777777777'
    expectRejected(
      await establishInitiatorSession(e.expected, e.session, e.responderKeys, e.ephA.privateKey),
      /session id does not match/,
    )
  })

  it('never derives keys from an ACTIVE session whose peer authentication is invalid', async () => {
    // The server reports ACTIVE with incomplete material: fail closed.
    const a = await initiatorFixture()
    expect(a.session.status).toBe('ACTIVE')
    a.session.responderSignature = null
    expectRejected(
      await establishInitiatorSession(a.expected, a.session, a.responderKeys, a.ephA.privateKey),
      /responder handshake material is missing/,
    )

    // ACTIVE with complete-looking material signed by the wrong key: same
    // outcome — and the caller has no keys to send or decrypt with.
    const b = await initiatorFixture()
    const mallory = await generateIdentityKeyPair()
    b.session.responderSignature = await signTranscript(
      mallory.privateKey,
      fullTranscript(META, b.ephA.spkiB64, b.ephB.spkiB64),
    )
    const result = await establishInitiatorSession(b.expected, b.session, b.responderKeys, b.ephA.privateKey)
    expect(result.verified).toBe(false)
    expect('keys' in result).toBe(false)
  })
})
