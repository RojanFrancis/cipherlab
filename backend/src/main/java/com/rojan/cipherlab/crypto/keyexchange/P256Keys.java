package com.rojan.cipherlab.crypto.keyexchange;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * NIST P-256 helpers shared by the identity-key registry and the session
 * handshake. One implementation of "is this a real P-256 SubjectPublicKeyInfo"
 * gates both identity keys and ephemeral handshake keys — the handshake is
 * only as strong as the registry it trusts.
 */
public final class P256Keys {

    private P256Keys() {
    }

    /**
     * Parses DER SubjectPublicKeyInfo bytes and asserts they are a valid
     * NIST P-256 key. Fails closed with {@code INVALID_KEY}.
     */
    public static ECPublicKey parseSpki(byte[] der) {
        try {
            var publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (!(publicKey instanceof ECPublicKey ecKey)) {
                throw new InvalidRequestException("INVALID_KEY", "publicKey is not an EC public key.");
            }
            if (!isNistP256(ecKey.getParams())) {
                throw new InvalidRequestException("INVALID_KEY",
                        "EC keys must use the NIST P-256 (secp256r1) curve.");
            }
            return ecKey;
        } catch (InvalidRequestException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new InvalidRequestException("INVALID_KEY",
                    "publicKey is not a valid EC X.509 SubjectPublicKeyInfo.");
        }
    }

    /** Base64 variant of {@link #parseSpki(byte[])}. */
    public static ECPublicKey parseSpkiBase64(String publicKeyBase64) {
        byte[] der;
        try {
            der = Base64.getDecoder().decode(publicKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("INVALID_KEY", "The public key must be Base64-encoded.");
        }
        return parseSpki(der);
    }

    /**
     * Verifies an ECDSA P-256 / SHA-256 signature (DER, as produced by JCA
     * and by the frontend's DER wrapper) over {@code message}. Returns
     * {@code false} on <i>any</i> malformed input — wrong key type, bad
     * Base64, unparseable signature. Never throws.
     */
    public static boolean verifies(String publicKeySpkiBase64, byte[] message,
                                   String signatureDerBase64) {
        try {
            ECPublicKey publicKey = parseSpkiBase64(publicKeySpkiBase64);
            byte[] signature = Base64.getDecoder().decode(signatureDerBase64);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (InvalidRequestException | IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Curve check by identity of the standard parameters: P-256's group
     * order and generator are its fingerprint. (ECCurve does not override
     * equals, so order + generator + field size is the reliable comparison.)
     */
    public static boolean isNistP256(ECParameterSpec params) {
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
}
