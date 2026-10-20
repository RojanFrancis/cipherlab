package com.rojan.cipherlab.messaging;

import java.util.UUID;

/**
 * The canonical session transcript — the exact byte string both parties
 * sign with their identity keys during the handshake, and the exact byte
 * string the server re-derives to verify those signatures.
 *
 * <h2>Protocol (v1, deliberately narrow)</h2>
 * <ol>
 *   <li><b>Initiator</b> generates an <em>ephemeral</em> P-256 keypair and
 *       {@code POST}s {@code sessionId, suite, ephA, sigA, identityKeyId},
 *       where {@code sigA = ECDSA-SHA256(identityPrivateKey_A,
 *       transcript.initiatorForm(...))}. The server checks the identity key
 *       belongs to the caller, is not revoked, and that {@code sigA}
 *       verifies — otherwise 400. Session status: PENDING.</li>
 *   <li><b>Responder</b> fetches the session (seeing {@code ephA}),
 *       independently verifies {@code sigA} against the initiator's
 *       published identity key, generates their own ephemeral keypair, and
 *       {@code POST}s {@code ephB, sigB, identityKeyId} to
 *       {@code /activate}. The server verifies {@code sigB} over the FULL
 *       transcript (now including {@code ephB}) before the session may
 *       become ACTIVE.</li>
 *   <li>Both clients derive keys from {@code ECDH(ephA, ephB)} with
 *       HKDF-SHA-256 using the full transcript as context (done strictly
 *       client-side; the server never sees the shared secret).</li>
 * </ol>
 *
 * <b>Why two transcript forms:</b> the initiator must sign before the
 * responder's ephemeral key exists, so {@code sigA} covers the prefix form
 * and {@code sigB} covers the complete form. Both are bound to
 * sessionId + conversation + both user ids + suite, so a transcript cannot
 * be replayed into another session, conversation, or pair of users.
 *
 * <b>Wire compatibility:</b> the frontend ({@code frontend/src/lib/e2ee.ts})
 * reconstructs these strings byte-for-byte. Any change here is a breaking
 * protocol change — bump {@link #PREFIX} if the format ever changes.
 */
public final class SessionTranscript {

    /** Protocol version label — part of every transcript, never changes in place. */
    public static final String PREFIX = "cipherlab-session-v1";

    /** The only suite this protocol implements (Web Crypto: P-256 ECDH). */
    public static final String SUITE = "EC_P256+HKDF-SHA256+AES-256-GCM";

    private SessionTranscript() {
    }

    /**
     * What the initiator signs at creation time:
     * {@code prefix|sessionId|conversationId|initiatorId|responderId|suite|A:ephA}
     */
    public static String initiatorForm(UUID sessionId, UUID conversationId,
                                       UUID initiatorId, UUID responderId,
                                       String suite, String initiatorEphemeralBase64) {
        return PREFIX + "|" + sessionId + "|" + conversationId + "|" + initiatorId
                + "|" + responderId + "|" + suite + "|A:" + initiatorEphemeralBase64;
    }

    /**
     * What the responder signs at activation, and what both sides use as
     * key-derivation context: the initiator form plus {@code |B:ephB}.
     */
    public static String fullForm(UUID sessionId, UUID conversationId,
                                  UUID initiatorId, UUID responderId,
                                  String suite, String initiatorEphemeralBase64,
                                  String responderEphemeralBase64) {
        return initiatorForm(sessionId, conversationId, initiatorId, responderId,
                suite, initiatorEphemeralBase64) + "|B:" + responderEphemeralBase64;
    }
}
