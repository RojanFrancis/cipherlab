package com.rojan.cipherlab.identity;

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
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Identity key endpoints (authenticated). Publish/list/revoke operate on the
 * caller's own keys; the {@code /users/{id}/keys} route is the peer lookup
 * used before starting a session.
 */
@RestController
@RequestMapping("/api/v1/identity")
public class IdentityKeyController {

    private final IdentityKeyService identityKeyService;

    public IdentityKeyController(IdentityKeyService identityKeyService) {
        this.identityKeyService = identityKeyService;
    }

    @PostMapping("/keys")
    public ResponseEntity<IdentityKeyService.KeyResponse> publish(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @Valid @RequestBody PublishKeyRequest request) {
        IdentityKeyService.KeyResponse key = identityKeyService.publish(
                principal.userId(), request.keyType(), request.publicKey());
        return ResponseEntity.status(HttpStatus.CREATED).body(key);
    }

    @GetMapping("/keys")
    public List<IdentityKeyService.KeyResponse> listMine(
            @AuthenticationPrincipal AuthenticatedUser principal) {
        return identityKeyService.listMine(principal.userId());
    }

    @PostMapping("/keys/{keyId}/revoke")
    public IdentityKeyService.KeyResponse revoke(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @PathVariable UUID keyId) {
        return identityKeyService.revoke(principal.userId(), keyId);
    }

    /** Peer lookup: fetch another user's published keys before encrypting to them. */
    @GetMapping("/users/{userId}/keys")
    public List<IdentityKeyService.KeyResponse> listForUser(@PathVariable UUID userId) {
        return identityKeyService.listForUser(userId);
    }

    public record PublishKeyRequest(
            @NotBlank @Size(max = 32)
            @Pattern(regexp = "EC_P256|RSA_2048",
                    message = "must be one of EC_P256, RSA_2048")
            String keyType,
            @NotBlank @Size(max = 512) String publicKey) {
    }
}
