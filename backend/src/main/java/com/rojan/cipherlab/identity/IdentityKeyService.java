package com.rojan.cipherlab.identity;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.rojan.cipherlab.common.AuditService;
import com.rojan.cipherlab.common.ConflictException;
import com.rojan.cipherlab.common.InvalidRequestException;
import com.rojan.cipherlab.common.NotFoundException;
import com.rojan.cipherlab.crypto.hashing.HashingService;

/**
 * Public identity key registry.
 *
 * <p>The threat this exists to solve (spec §2): an attacker who controls the
 * server can hand out <em>their own</em> public key to Alice when she asks
 * for Bob's — the classic key-substitution / MITM move the lab simulates.
 * Publishing keys with <b>fingerprints</b> gives users an out-of-band value
 * they can compare ("does your fingerprint end in 7F3A?"), which no server
 * can silently rewrite.
 *
 * <p>Client-generated, client-held rule: the server only ever receives the
 * <b>public</b> half. If this table leaks, no private material leaks with
 * it. Rotation increments {@code key_version} instead of overwriting, so
 * signatures made under the old key stay verifiable and revocation is an
 * explicit, auditable act.
 */
@Service
public class IdentityKeyService {

    private final IdentityKeyRepository identityKeyRepository;
    private final AuditService auditService;
    private final HashingService hashingService;

    public IdentityKeyService(IdentityKeyRepository identityKeyRepository,
                              AuditService auditService,
                              HashingService hashingService) {
        this.identityKeyRepository = identityKeyRepository;
        this.auditService = auditService;
        this.hashingService = hashingService;
    }

    /** Key types this registry accepts — messaging identity uses EC_P256. */
    private static final Set<String> SUPPORTED_KEY_TYPES = Set.of("EC_P256", "RSA_2048");

    private static final int RSA_MODULUS_BITS = 2048;

    /**
     * Publish a public key for the current user. Keys are always bound to the
     * <b>authenticated</b> caller — a client can never publish on someone
     * else's behalf. The submitted material is <b>parsed and validated</b>
     * against its declared type (a real P-256 X.509 SubjectPublicKeyInfo,
     * or a 2048-bit RSA key): random bytes labeled {@code EC_P256} are
     * rejected, because a registry that stores garbage would make the
     * handshake that trusts it garbage too.
     *
     * <p>The fingerprint is recomputed server-side from the submitted key
     * bytes — a client-supplied fingerprint would defeat the whole point.
     * Only the <b>public</b> half ever reaches the server; private halves
     * are generated and held by the client and are never uploaded, logged
     * or persisted here.
     */
    @Transactional
    public KeyResponse publish(UUID userId, String keyType, String publicKeyBase64) {
        if (!SUPPORTED_KEY_TYPES.contains(keyType)) {
            throw new InvalidRequestException("INVALID_KEY_TYPE",
                    "Unsupported key type. Use EC_P256 or RSA_2048.");
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException(
                    "INVALID_KEY", "The public key must be Base64-encoded.");
        }
        if (keyBytes.length == 0 || keyBytes.length > 384) {
            throw new InvalidRequestException(
                    "INVALID_KEY", "Public key must decode to 1-384 bytes.");
        }
        validateKeyMaterial(keyType, keyBytes);
        int nextVersion = identityKeyRepository.countByUserId(userId) + 1;
        String fingerprint = hashingService.digestBytes(keyBytes, "SHA-256");
        IdentityKey key = identityKeyRepository.save(
                IdentityKey.create(userId, keyType, publicKeyBase64, fingerprint, nextVersion));
        auditService.record(userId, "IDENTITY_KEY_PUBLISHED", key.getId().toString());
        return KeyResponse.of(key);
    }

    /**
     * Parses the DER bytes with the JCA and asserts they match the declared
     * type and parameters. Fails closed: anything unparseable, the wrong
     * curve, or the wrong modulus size is rejected with INVALID_KEY.
     */
    private static void validateKeyMaterial(String keyType, byte[] der) {
        try {
            switch (keyType) {
                case "EC_P256" -> {
                    PublicKey publicKey = KeyFactory.getInstance("EC")
                            .generatePublic(new X509EncodedKeySpec(der));
                    if (!(publicKey instanceof ECPublicKey ecKey)) {
                        throw invalidKey("publicKey is not an EC public key.");
                    }
                    if (!isNistP256(ecKey.getParams())) {
                        throw invalidKey("EC identity keys must use the NIST P-256 (secp256r1) curve.");
                    }
                }
                case "RSA_2048" -> {
                    PublicKey publicKey = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(der));
                    if (!(publicKey instanceof RSAPublicKey rsaKey)) {
                        throw invalidKey("publicKey is not an RSA public key.");
                    }
                    if (rsaKey.getModulus().bitLength() != RSA_MODULUS_BITS) {
                        throw invalidKey("RSA identity keys must have a 2048-bit modulus.");
                    }
                }
                default -> throw invalidKey("Unsupported key type: " + keyType);
            }
        } catch (InvalidRequestException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw invalidKey("publicKey is not a valid X.509 SubjectPublicKeyInfo for "
                    + keyType + ".");
        }
    }

    /**
     * Curve check by identity of the standard parameters: P-256's group order
     * and generator are its fingerprint. (ECCurve does not override equals,
     * so order + generator + field size is the reliable comparison.)
     */
    private static boolean isNistP256(ECParameterSpec params) {
        try {
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec reference = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            return params.getCurve().getField().getFieldSize() == 256
                    && params.getOrder().equals(reference.getOrder())
                    && params.getGenerator().equals(reference.getGenerator());
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static InvalidRequestException invalidKey(String message) {
        return new InvalidRequestException("INVALID_KEY", message);
    }

    /** The user's key history, newest version first. */
    @Transactional(readOnly = true)
    public List<KeyResponse> listMine(UUID userId) {
        return identityKeyRepository.findByUserIdOrderByKeyVersionDesc(userId).stream()
                .map(KeyResponse::of)
                .toList();
    }

    /** Revoke a key the caller owns. Revocation is final — never deleted. */
    @Transactional
    public KeyResponse revoke(UUID userId, UUID keyId) {
        IdentityKey key = identityKeyRepository.findByIdAndUserId(keyId, userId)
                .orElseThrow(NotFoundException::new);
        if (key.isRevoked()) {
            throw new ConflictException("KEY_ALREADY_REVOKED", "That key is already revoked.");
        }
        key.revoke();
        identityKeyRepository.save(key);
        auditService.record(userId, "IDENTITY_KEY_REVOKED", keyId.toString());
        return KeyResponse.of(key);
    }

    /** Public view of any user's keys — what a peer fetches before encrypting. */
    @Transactional(readOnly = true)
    public List<KeyResponse> listForUser(UUID targetUserId) {
        return identityKeyRepository.findByUserIdOrderByKeyVersionDesc(targetUserId).stream()
                .map(KeyResponse::of)
                .toList();
    }

    /**
     * Wire shape. The fingerprint is the SHA-256 of the DER public key,
     * hex-encoded — short enough to read aloud and compare.
     */
    public record KeyResponse(UUID id, UUID userId, String keyType, String publicKey,
                              String fingerprint, int keyVersion,
                              java.time.LocalDateTime createdAt, boolean revoked,
                              java.time.LocalDateTime revokedAt) {
        static KeyResponse of(IdentityKey key) {
            return new KeyResponse(key.getId(), key.getUserId(), key.getKeyType(),
                    key.getPublicKey(), key.getFingerprint(), key.getKeyVersion(),
                    key.getCreatedAt(), key.isRevoked(), key.getRevokedAt());
        }
    }
}
