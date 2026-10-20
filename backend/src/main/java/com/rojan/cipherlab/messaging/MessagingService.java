package com.rojan.cipherlab.messaging;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.rojan.cipherlab.auth.UserRepository;
import com.rojan.cipherlab.common.AuditService;
import com.rojan.cipherlab.common.ConflictException;
import com.rojan.cipherlab.common.InvalidRequestException;
import com.rojan.cipherlab.common.NotFoundException;
import com.rojan.cipherlab.crypto.hashing.HashingService;
import com.rojan.cipherlab.crypto.keyexchange.P256Keys;
import com.rojan.cipherlab.identity.IdentityKey;
import com.rojan.cipherlab.identity.IdentityKeyRepository;

/**
 * Conversations, the <b>authenticated session handshake</b>, and the
 * ciphertext relay.
 *
 * <p><b>The server's job is narrow on purpose:</b> decide who may send to
 * whom (membership), verify that both parties of a session agreed on the
 * same ephemeral keys (signatures over the canonical transcript, see
 * {@link SessionTranscript}), track lifecycle, store opaque ciphertext, and
 * detect replays. It holds no private or derived key material and cannot
 * read a single byte of payload.
 *
 * <p><b>ACTIVE means the handshake happened</b> — not merely that someone
 * clicked: activation requires the responder's ephemeral public key plus a
 * valid identity signature over the full transcript, verified server-side
 * against the caller's registered (non-revoked) identity key. The responder
 * independently re-verifies the initiator's signature client-side, so
 * neither party trusts the server's word for authenticity.
 *
 * <p><b>Replay rejection</b> rides on the database, not on application
 * guesses: the unique index {@code (session_id, sender_id, sequence_number)}
 * makes duplicate submission physically impossible to store. The service
 * pre-checks for a clean 400, and still catches the constraint violation so
 * a concurrent double-submit cannot slip through — the index is the source
 * of truth, the check is just courtesy.
 */
@Service
public class MessagingService {

    private static final Logger log = LoggerFactory.getLogger(MessagingService.class);

    /** AES-GCM with a 96-bit nonce, per NIST SP 800-38D §8.2.2. */
    private static final int GCM_NONCE_BYTES = 12;
    /** Ciphertext below the tag size (16 bytes) cannot be a valid envelope. */
    private static final int GCM_MIN_CIPHERTEXT_BYTES = 16;

    private final ConversationRepository conversationRepository;
    private final ConversationMemberRepository memberRepository;
    private final CryptoSessionRepository sessionRepository;
    private final MessageRepository messageRepository;
    private final UserRepository userRepository;
    private final IdentityKeyRepository identityKeyRepository;
    private final AuditService auditService;
    private final HashingService hashingService;

    /** Session lifetime once activated (spec §7: sessions expire, not forever). */
    static final int SESSION_TTL_HOURS = 24;

    public MessagingService(ConversationRepository conversationRepository,
                            ConversationMemberRepository memberRepository,
                            CryptoSessionRepository sessionRepository,
                            MessageRepository messageRepository,
                            UserRepository userRepository,
                            IdentityKeyRepository identityKeyRepository,
                            AuditService auditService,
                            HashingService hashingService) {
        this.conversationRepository = conversationRepository;
        this.memberRepository = memberRepository;
        this.sessionRepository = sessionRepository;
        this.messageRepository = messageRepository;
        this.userRepository = userRepository;
        this.identityKeyRepository = identityKeyRepository;
        this.auditService = auditService;
        this.hashingService = hashingService;
    }

    // ---------------------------------------------------------------- conversations

    /** Create a two-party conversation. Both parties must exist; self is rejected. */
    @Transactional
    public ConversationResponse createConversation(UUID ownerId, UUID partnerId) {
        if (ownerId.equals(partnerId)) {
            throw new InvalidRequestException("INVALID_REQUEST", "Cannot start a conversation with yourself.");
        }
        if (!userRepository.existsById(partnerId)) {
            throw new NotFoundException("No user with that id.");
        }
        Conversation conversation = conversationRepository.save(Conversation.create());
        memberRepository.save(ConversationMember.of(conversation.getId(), ownerId));
        memberRepository.save(ConversationMember.of(conversation.getId(), partnerId));
        auditService.record(ownerId, "CONVERSATION_CREATED", conversation.getId().toString());
        return ConversationResponse.of(conversation, List.of(ownerId, partnerId));
    }

    /** Conversations the caller belongs to, with member ids. */
    @Transactional(readOnly = true)
    public List<ConversationResponse> listConversations(UUID userId) {
        return memberRepository.findByUserId(userId).stream()
                .map(ConversationMember::getConversationId)
                .distinct()
                .map(conversationId -> {
                    Conversation conversation = conversationRepository.findById(conversationId)
                            .orElseThrow(NotFoundException::new);
                    List<UUID> members = memberRepository.findByConversationId(conversationId).stream()
                            .map(ConversationMember::getUserId)
                            .toList();
                    return ConversationResponse.of(conversation, members);
                })
                .toList();
    }

    // ---------------------------------------------------------------- sessions (handshake)

    /**
     * Initiator opens a session with their <b>signed ephemeral public key</b>.
     *
     * <p>Validated here, server-side: the identity key exists, belongs to the
     * caller, is not revoked and is EC_P256; the ephemeral is a real P-256
     * SubjectPublicKeyInfo; and the signature verifies over the canonical
     * initiator transcript ({@link SessionTranscript#initiatorForm}). Any
     * failure is 400 — the session never enters PENDING with material the
     * peer could not verify.
     */
    @Transactional
    public SessionResponse createSession(UUID userId, UUID conversationId, String suite,
                                         UUID sessionId, String ephemeralPublic,
                                         String signature, UUID identityKeyId) {
        requireMember(conversationId, userId);
        if (!SessionTranscript.SUITE.equals(suite)) {
            throw new InvalidRequestException("INVALID_REQUEST",
                    "Unsupported suite. Use " + SessionTranscript.SUITE + ".");
        }
        UUID partnerId = memberRepository.findByConversationId(conversationId).stream()
                .map(ConversationMember::getUserId)
                .filter(id -> !id.equals(userId))
                .findFirst()
                .orElseThrow(() -> new InvalidRequestException("INVALID_REQUEST",
                        "A session needs exactly two members."));
        if (sessionRepository.existsById(sessionId)) {
            throw new ConflictException("SESSION_ID_TAKEN", "That session id is already in use.");
        }
        IdentityKey identityKey = requireUsableIdentityKey(userId, identityKeyId);
        P256Keys.parseSpkiBase64(ephemeralPublic);

        String transcript = SessionTranscript.initiatorForm(
                sessionId, conversationId, userId, partnerId, suite, ephemeralPublic);
        requireValidSignature(identityKey, transcript, signature);

        CryptoSession session = sessionRepository.save(CryptoSession.create(
                sessionId, conversationId, userId, partnerId, suite,
                ephemeralPublic, signature, identityKeyId));
        auditService.record(userId, "SESSION_HANDSHAKE_INITIATED", session.getId().toString());
        return SessionResponse.of(session);
    }

    /**
     * Responder completes the handshake. Activation now <b>requires</b> the
     * responder's signed ephemeral: the server verifies the signature over
     * the FULL transcript (including the initiator's ephemeral) against the
     * responder's own registered identity key before status may become
     * ACTIVE. A session can therefore never be active without a completed,
     * authenticated key agreement on record.
     */
    @Transactional
    public SessionResponse activateSession(UUID userId, UUID sessionId,
                                           String ephemeralPublic, String signature,
                                           UUID identityKeyId) {
        CryptoSession session = sessionRepository.findById(sessionId).orElseThrow(NotFoundException::new);
        if (!session.isParticipant(userId)) {
            // Not a participant: 404, same as nonexistent — no existence oracle.
            throw new NotFoundException();
        }
        if (!session.getResponderId().equals(userId)) {
            throw new ConflictException("NOT_RESPONDER", "Only the responder can activate this session.");
        }
        if (!CryptoSession.STATUS_PENDING.equals(session.getStatus())) {
            throw new ConflictException("SESSION_NOT_PENDING",
                    "Session is " + session.getStatus() + " and cannot be activated.");
        }
        IdentityKey identityKey = requireUsableIdentityKey(userId, identityKeyId);
        P256Keys.parseSpkiBase64(ephemeralPublic);

        String transcript = SessionTranscript.fullForm(
                session.getId(), session.getConversationId(),
                session.getInitiatorId(), session.getResponderId(), session.getSuite(),
                session.getInitiatorEphemeralPublic(), ephemeralPublic);
        requireValidSignature(identityKey, transcript, signature);

        session.completeHandshake(ephemeralPublic, signature, identityKeyId,
                hashingService.digestBytes(transcript.getBytes(StandardCharsets.UTF_8), "SHA-256"));
        session.activate(LocalDateTime.now(ZoneOffset.UTC).plusHours(SESSION_TTL_HOURS));
        sessionRepository.save(session);
        auditService.record(userId, "SESSION_ACTIVATED", sessionId.toString());
        return SessionResponse.of(session);
    }

    @Transactional(readOnly = true)
    public SessionResponse getSession(UUID userId, UUID sessionId) {
        CryptoSession session = sessionRepository.findById(sessionId).orElseThrow(NotFoundException::new);
        if (!session.isParticipant(userId)) {
            throw new NotFoundException();
        }
        return SessionResponse.of(session);
    }

    /** The identity key must belong to the caller, be EC_P256, and not be revoked. */
    private IdentityKey requireUsableIdentityKey(UUID userId, UUID identityKeyId) {
        IdentityKey key = identityKeyRepository.findByIdAndUserId(identityKeyId, userId)
                .orElseThrow(() -> new InvalidRequestException("INVALID_IDENTITY_KEY",
                        "No such identity key for this user."));
        if (key.isRevoked()) {
            throw new InvalidRequestException("INVALID_IDENTITY_KEY",
                    "That identity key is revoked; publish a fresh key and retry.");
        }
        if (!"EC_P256".equals(key.getKeyType())) {
            throw new InvalidRequestException("INVALID_IDENTITY_KEY",
                    "Session handshakes require an EC_P256 identity key.");
        }
        return key;
    }

    private void requireValidSignature(IdentityKey identityKey, String transcript, String signature) {
        boolean valid = P256Keys.verifies(identityKey.getPublicKey(),
                transcript.getBytes(StandardCharsets.UTF_8), signature);
        if (!valid) {
            throw new InvalidRequestException("HANDSHAKE_SIGNATURE_INVALID",
                    "The identity signature does not verify over the canonical transcript.");
        }
    }

    // ---------------------------------------------------------------- relay

    /**
     * Relay one ciphertext envelope. The server validates <b>authorization,
     * lifecycle and envelope shape</b> but never content: it cannot
     * distinguish "hello" from gibberish, and that is the point. The nonce
     * must be a fresh 96-bit GCM nonce (12 bytes) and the ciphertext must
     * at least carry the 16-byte tag — structural checks only; no key is
     * involved.
     *
     * <p>Replay path: a repeated (session, sender, sequence) triple trips
     * the unique index; we answer 400 REPLAYED_MESSAGE and write an audit
     * row, because a replay <em>attempt</em> is exactly the security event
     * the operator wants to see.
     */
    @Transactional
    public MessageResponse relay(UUID senderId, UUID sessionId, long sequenceNumber,
                                 String nonce, String ciphertext) {
        CryptoSession session = sessionRepository.findById(sessionId).orElseThrow(NotFoundException::new);
        if (!session.isParticipant(senderId)) {
            throw new NotFoundException();
        }
        if (!CryptoSession.STATUS_ACTIVE.equals(session.getStatus())) {
            throw new ConflictException("SESSION_NOT_ACTIVE",
                    "Session must be ACTIVE before relaying messages.");
        }
        if (session.isExpiredAt(LocalDateTime.now(ZoneOffset.UTC))) {
            throw new ConflictException("SESSION_EXPIRED", "This session has expired.");
        }
        if (sequenceNumber < 0) {
            throw new InvalidRequestException("INVALID_REQUEST", "sequenceNumber must be >= 0.");
        }
        byte[] nonceBytes = decodeBase64(nonce, "INVALID_NONCE", "nonce must be Base64-encoded.");
        if (nonceBytes.length != GCM_NONCE_BYTES) {
            throw new InvalidRequestException("INVALID_NONCE",
                    "AES-GCM nonce must be exactly 12 bytes (96 bits).");
        }
        byte[] ciphertextBytes = decodeBase64(ciphertext, "INVALID_CIPHERTEXT",
                "ciphertext must be Base64-encoded.");
        if (ciphertextBytes.length < GCM_MIN_CIPHERTEXT_BYTES) {
            throw new InvalidRequestException("INVALID_CIPHERTEXT",
                    "ciphertext must be at least 16 bytes — it must carry the GCM authentication tag.");
        }
        if (messageRepository.existsBySessionIdAndSenderIdAndSequenceNumber(sessionId, senderId, sequenceNumber)) {
            // Audited in its own transaction so the evidence survives the
            // rejection that follows — a replay attempt is the row an
            // operator most needs to see.
            auditService.recordSecurityEvent(senderId, "REPLAY_REJECTED", sessionId.toString());
            log.warn("Replay rejected: sender {} sequence {} on session {}", senderId, sequenceNumber, sessionId);
            throw new InvalidRequestException("REPLAYED_MESSAGE",
                    "This (session, sender, sequence) has already been relayed.");
        }
        Message message;
        try {
            message = messageRepository.saveAndFlush(Message.relayed(
                    session.getConversationId(), sessionId, senderId, sequenceNumber, nonce, ciphertext));
        } catch (DataIntegrityViolationException e) {
            // Concurrent double-submit: the index caught it mid-flight.
            auditService.recordSecurityEvent(senderId, "REPLAY_REJECTED", sessionId.toString());
            throw new InvalidRequestException("REPLAYED_MESSAGE",
                    "This (session, sender, sequence) has already been relayed.");
        }
        return MessageResponse.of(message);
    }

    /** Conversation history for members only — non-members get 404. */
    @Transactional(readOnly = true)
    public List<MessageResponse> listMessages(UUID userId, UUID conversationId) {
        requireMember(conversationId, userId);
        return messageRepository.findByConversationIdOrderByCreatedAtAsc(conversationId).stream()
                .map(MessageResponse::of)
                .toList();
    }

    private void requireMember(UUID conversationId, UUID userId) {
        if (!memberRepository.existsByConversationIdAndUserId(conversationId, userId)) {
            // 404 rather than 403: membership must not be probe-able.
            throw new NotFoundException();
        }
    }

    private static byte[] decodeBase64(String value, String code, String message) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException(code, message);
        }
    }

    // ---------------------------------------------------------------- wire types

    public record ConversationResponse(UUID id, List<UUID> memberIds, LocalDateTime createdAt) {
        static ConversationResponse of(Conversation conversation, List<UUID> memberIds) {
            return new ConversationResponse(conversation.getId(), memberIds, conversation.getCreatedAt());
        }
    }

    /**
     * Session view including the public handshake material — exactly what
     * the peer needs to verify signatures and derive keys client-side.
     * No private or derived key material exists anywhere in this shape.
     */
    public record SessionResponse(UUID id, UUID conversationId, UUID initiatorId, UUID responderId,
                                  String suite, String status, LocalDateTime createdAt,
                                  LocalDateTime expiresAt,
                                  String initiatorEphemeralPublic, String initiatorSignature,
                                  UUID initiatorIdentityKeyId,
                                  String responderEphemeralPublic, String responderSignature,
                                  UUID responderIdentityKeyId, String transcriptHash) {
        static SessionResponse of(CryptoSession session) {
            return new SessionResponse(session.getId(), session.getConversationId(),
                    session.getInitiatorId(), session.getResponderId(), session.getSuite(),
                    session.getStatus(), session.getCreatedAt(), session.getExpiresAt(),
                    session.getInitiatorEphemeralPublic(), session.getInitiatorSignature(),
                    session.getInitiatorIdentityKeyId(),
                    session.getResponderEphemeralPublic(), session.getResponderSignature(),
                    session.getResponderIdentityKeyId(), session.getTranscriptHash());
        }
    }

    /** The relay never returns decrypted content — only the envelope. */
    public record MessageResponse(UUID id, UUID conversationId, UUID sessionId, UUID senderId,
                                  long sequenceNumber, String nonce, String ciphertext,
                                  LocalDateTime createdAt) {
        static MessageResponse of(Message message) {
            return new MessageResponse(message.getId(), message.getConversationId(),
                    message.getSessionId(), message.getSenderId(), message.getSequenceNumber(),
                    message.getNonce(), message.getCiphertext(), message.getCreatedAt());
        }
    }
}
