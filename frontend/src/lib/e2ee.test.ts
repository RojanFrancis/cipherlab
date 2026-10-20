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
  fingerprintOfSpki,
  fromB64,
  toB64,
} from './e2ee'
import type { HandshakeMeta, MessageMeta } from './e2ee'

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
