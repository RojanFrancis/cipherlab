package com.rojan.cipherlab.auth;

import java.time.ZoneOffset;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.rojan.cipherlab.common.AuditService;
import com.rojan.cipherlab.common.ConflictException;
import com.rojan.cipherlab.common.UnauthorizedException;
import com.rojan.cipherlab.security.JwtService;

/**
 * Registration and login.
 *
 * <p>Passwords are hashed with <b>BCrypt</b> (cost 10): a deliberately slow,
 * salted, memory-hard-ish KDF. The contrast with the lab's SHA-256 is the
 * lesson — SHA-256 is optimized to be fast (good for integrity checks),
 * which is exactly what you do <em>not</em> want when an attacker holds a
 * database of hashes and can try billions of guesses per second.
 *
 * <p>Login answers with the same error for "unknown user" and "wrong
 * password" so the endpoint is not a username oracle.
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final AuditService auditService;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthService(UserRepository userRepository,
                       AuditService auditService,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
        this.jwtService = jwtService;
    }

    @Transactional
    public User register(String username, String email, String rawPassword) {
        if (userRepository.existsByUsername(username)) {
            throw new ConflictException("DUPLICATE_USERNAME", "That username is already taken.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new ConflictException("DUPLICATE_EMAIL", "That email is already registered.");
        }
        User user;
        try {
            user = userRepository.save(User.create(username, email, passwordEncoder.encode(rawPassword)));
        } catch (DataIntegrityViolationException e) {
            // Lost the race against a concurrent registration — treat exactly
            // like the pre-check above so the response is indistinguishable.
            throw new ConflictException("DUPLICATE_USERNAME", "That username is already taken.");
        }
        auditService.record(user.getId(), "USER_REGISTERED", user.getId().toString());
        log.info("Registered user {}", user.getId());
        return user;
    }

    @Transactional(readOnly = true)
    public TokenPair login(String username, String rawPassword) {
        User user = userRepository.findByUsername(username).orElseThrow(UnauthorizedException::new);
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            // Do not log which factor failed; one generic audit row suffices.
            // recordSecurityEvent: the throw below rolls back this
            // transaction, and the evidence must outlive it.
            auditService.recordSecurityEvent(user.getId(), "LOGIN_FAILED", user.getId().toString());
            throw new UnauthorizedException();
        }
        auditService.record(user.getId(), "LOGIN_SUCCEEDED", user.getId().toString());
        String token = jwtService.issueToken(user.getId(), user.getUsername());
        return new TokenPair(token, "Bearer", user);
    }

    /** Full profile for {@code /me}; email and createdAt come from the row. */
    @Transactional(readOnly = true)
    public UserResponse profile(UUID userId) {
        User user = userRepository.findById(userId).orElseThrow(UnauthorizedException::new);
        return UserResponse.of(user);
    }

    /** Access token plus the public profile — never the password hash. */
    public record TokenPair(String accessToken, String tokenType, User user) {
    }

    public record UserResponse(UUID id, String username, String email,
                               java.time.LocalDateTime createdAt) {
        static UserResponse of(User user) {
            return new UserResponse(user.getId(), user.getUsername(), user.getEmail(),
                    user.getCreatedAt());
        }
    }

    public record RegisterResponse(UUID id, String username, String email,
                                   java.time.LocalDateTime createdAt) {
        static RegisterResponse of(User user) {
            return new RegisterResponse(user.getId(), user.getUsername(), user.getEmail(),
                    user.getCreatedAt());
        }
    }

    public record LoginResponse(String accessToken, String tokenType, long expiresInSeconds,
                                UserResponse user) {
    }

    public LoginResponse loginResponse(TokenPair pair, long ttlSeconds) {
        return new LoginResponse(pair.accessToken(), pair.tokenType(), ttlSeconds,
                UserResponse.of(pair.user()));
    }
}
