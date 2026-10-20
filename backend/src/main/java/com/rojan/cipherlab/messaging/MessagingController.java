package com.rojan.cipherlab.messaging;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rojan.cipherlab.security.AuthenticatedUser;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

/**
 * Messaging endpoints (authenticated). Every route resolves the caller from
 * the token — a client can never name a different sender.
 */
@RestController
@RequestMapping("/api/v1")
public class MessagingController {

    private final MessagingService messagingService;

    public MessagingController(MessagingService messagingService) {
        this.messagingService = messagingService;
    }

    // ---------------------------------------------------------------- conversations

    @PostMapping("/conversations")
    public ResponseEntity<MessagingService.ConversationResponse> createConversation(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @Valid @RequestBody CreateConversationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(messagingService.createConversation(principal.userId(), request.partnerId()));
    }

    @GetMapping("/conversations")
    public List<MessagingService.ConversationResponse> listConversations(
            @AuthenticationPrincipal AuthenticatedUser principal) {
        return messagingService.listConversations(principal.userId());
    }

    @GetMapping("/conversations/{conversationId}/messages")
    public List<MessagingService.MessageResponse> listMessages(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID conversationId) {
        return messagingService.listMessages(principal.userId(), conversationId);
    }

    // ---------------------------------------------------------------- sessions

    @PostMapping("/conversations/{conversationId}/sessions")
    public ResponseEntity<MessagingService.SessionResponse> createSession(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID conversationId,
            @Valid @RequestBody CreateSessionRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(messagingService.createSession(principal.userId(), conversationId,
                        request.suite(), request.sessionId(), request.ephemeralPublic(),
                        request.signature(), request.identityKeyId()));
    }

    @GetMapping("/conversations/{conversationId}/sessions")
    public List<MessagingService.SessionResponse> listSessions(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID conversationId) {
        return messagingService.listSessions(principal.userId(), conversationId);
    }

    @GetMapping("/sessions/{sessionId}")
    public MessagingService.SessionResponse getSession(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID sessionId) {
        return messagingService.getSession(principal.userId(), sessionId);
    }

    @PostMapping("/sessions/{sessionId}/activate")
    public MessagingService.SessionResponse activateSession(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID sessionId,
            @Valid @RequestBody ActivateSessionRequest request) {
        return messagingService.activateSession(principal.userId(), sessionId,
                request.ephemeralPublic(), request.signature(), request.identityKeyId());
    }

    // ---------------------------------------------------------------- relay

    @PostMapping("/sessions/{sessionId}/messages")
    public ResponseEntity<MessagingService.MessageResponse> relay(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID sessionId,
            @Valid @RequestBody RelayRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(messagingService.relay(principal.userId(), sessionId,
                        request.sequenceNumber(), request.nonce(), request.ciphertext()));
    }

    // ---------------------------------------------------------------- requests

    public record CreateConversationRequest(@NotNull UUID partnerId) {
    }

    /**
     * Session creation carries the initiator's <b>signed ephemeral</b>:
     * {@code sessionId} is client-generated so both parties can sign the
     * same canonical transcript; {@code signature} is ECDSA P-256 over that
     * transcript with the caller's identity private key; {@code identityKeyId}
     * names the registered public key the server verifies against.
     */
    public record CreateSessionRequest(
            @NotNull UUID sessionId,
            @NotBlank @Size(max = 64)
            @Pattern(regexp = "EC_P256\\+HKDF-SHA256\\+AES-256-GCM",
                    message = "must be the supported suite label")
            String suite,
            @NotBlank @Size(max = 256) String ephemeralPublic,
            @NotBlank @Size(max = 256) String signature,
            @NotNull UUID identityKeyId) {
    }

    /** Activation carries the responder's signed ephemeral (same rules). */
    public record ActivateSessionRequest(
            @NotBlank @Size(max = 256) String ephemeralPublic,
            @NotBlank @Size(max = 256) String signature,
            @NotNull UUID identityKeyId) {
    }

    /**
     * The relay envelope. Nonce must be a 96-bit GCM nonce (12 bytes
     * Base64); ciphertext carries the AES-GCM result with its 16-byte tag
     * (Base64 of at least 16 decoded bytes, at most 48 KiB). The server
     * checks structure only — it has no key and cannot inspect content.
     */
    public record RelayRequest(
            @NotNull @PositiveOrZero Long sequenceNumber,
            @NotBlank @Size(max = 64) String nonce,
            @NotBlank @Size(max = 65536) String ciphertext) {
    }
}
