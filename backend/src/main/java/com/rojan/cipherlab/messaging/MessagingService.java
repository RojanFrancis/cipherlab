package com.rojan.cipherlab.messaging;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
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

/**
 * Conversations, crypto-session lifecycle, and the ciphertext relay.
 *
 * <p><b>The server's job is narrow on purpose:</b> decide who may send to
 * whom (membership), track session lifecycle (status/expiry), store
 * opaque ciphertext, and detect replays. It holds no keys and cannot read a
 * single byte of payload — the design lesson the whole project exists to
 * demonstrate (spec §2, §7).
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

    private final ConversationRepository conversationRepository;
    private final ConversationMemberRepository memberRepository;
    private final CryptoSessionRepository sessionRepository;
    private final MessageRepository messageRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    /** Session lifetime once activated (spec §7: sessions expire, not forever). */
    static final int SESSION_TTL_HOURS = 24;

    public MessagingService(ConversationRepository conversationRepository,
                            ConversationMemberRepository memberRepository,
                            CryptoSessionRepository sessionRepository,
                            MessageRepository messageRepository,
                            UserRepository userRepository,
                            AuditService auditService) {
        this.conversationRepository = conversationRepository;
        this.memberRepository = memberRepository;
        this.sessionRepository = sessionRepository;
        this.messageRepository = messageRepository;
        this.userRepository = userRepository;
        this.auditService = auditService;
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

    // ---------------------------------------------------------------- sessions

    /**
     * Initiator opens a session. Only {@code suite} metadata is recorded —
     * the clients perform the actual key agreement locally, so the server
     * cannot be tricked into holding a decryptable secret.
     */
    @Transactional
    public SessionResponse createSession(UUID userId, UUID conversationId, String suite) {
        requireMember(conversationId, userId);
        UUID partnerId = memberRepository.findByConversationId(conversationId).stream()
                .map(ConversationMember::getUserId)
                .filter(id -> !id.equals(userId))
                .findFirst()
                .orElseThrow(() -> new InvalidRequestException("INVALID_REQUEST",
                        "A session needs exactly two members."));
        CryptoSession session = sessionRepository.save(
                CryptoSession.create(conversationId, userId, partnerId, suite));
        auditService.record(userId, "SESSION_CREATED", session.getId().toString());
        return SessionResponse.of(session);
    }

    /**
     * Responder confirms the session, which activates it and starts the
     * expiry clock. Only the named responder may activate — the initiator
     * cannot unilaterally force an active session.
     */
    @Transactional
    public SessionResponse activateSession(UUID userId, UUID sessionId) {
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

    // ---------------------------------------------------------------- relay

    /**
     * Relay one ciphertext. The server validates <b>authorization and
     * ordering</b> but never content: it cannot distinguish "hello" from
     * gibberish, and that is the point.
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

    // ---------------------------------------------------------------- wire types

    public record ConversationResponse(UUID id, List<UUID> memberIds, LocalDateTime createdAt) {
        static ConversationResponse of(Conversation conversation, List<UUID> memberIds) {
            return new ConversationResponse(conversation.getId(), memberIds, conversation.getCreatedAt());
        }
    }

    public record SessionResponse(UUID id, UUID conversationId, UUID initiatorId, UUID responderId,
                                  String suite, String status, LocalDateTime createdAt,
                                  LocalDateTime expiresAt) {
        static SessionResponse of(CryptoSession session) {
            return new SessionResponse(session.getId(), session.getConversationId(),
                    session.getInitiatorId(), session.getResponderId(), session.getSuite(),
                    session.getStatus(), session.getCreatedAt(), session.getExpiresAt());
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
