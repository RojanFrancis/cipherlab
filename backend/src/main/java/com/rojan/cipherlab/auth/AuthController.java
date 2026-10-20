package com.rojan.cipherlab.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rojan.cipherlab.security.AuthenticatedUser;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Auth bootstrap (spec §6): the only two anonymous endpoints that touch user
 * data. Both are rate-limit-worthy in production — noted in the threat
 * model — and neither ever echoes a password or hash back.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final long jwtTtlSeconds;

    public AuthController(AuthService authService,
                          @Value("${cipherlab.security.jwt-ttl-seconds:3600}") long jwtTtlSeconds) {
        this.authService = authService;
        this.jwtTtlSeconds = jwtTtlSeconds;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthService.RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = authService.register(request.username(), request.email(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED).body(AuthService.RegisterResponse.of(user));
    }

    @PostMapping("/login")
    public AuthService.LoginResponse login(@Valid @RequestBody LoginRequest request) {
        AuthService.TokenPair pair = authService.login(request.username(), request.password());
        return authService.loginResponse(pair, jwtTtlSeconds);
    }

    /** Who am I? — proves the token round-trip end to end. */
    @GetMapping("/me")
    public AuthService.UserResponse me(@AuthenticationPrincipal AuthenticatedUser principal) {
        return authService.profile(principal.userId());
    }

    public record RegisterRequest(
            @NotBlank @Size(min = 3, max = 64) String username,
            @NotBlank @Email @Size(max = 255) String email,
            @NotBlank @Size(min = 8, max = 72) String password) {
    }

    public record LoginRequest(
            @NotBlank String username,
            @NotBlank String password) {
    }
}
