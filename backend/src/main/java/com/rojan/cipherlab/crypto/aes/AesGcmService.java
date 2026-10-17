package com.rojan.cipherlab.crypto.aes;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.rojan.cipherlab.common.AuthenticationFailedException;

/**
 * AES-256-GCM — the confidentiality + integrity workhorse of CipherLab.
 *
 * <h2>Why GCM and not ECB/CBC?</h2>
 * GCM is an <em>Authenticated Encryption with Associated Data</em> (AEAD)
 * mode: it encrypts (confidentiality) and computes a 128-bit authentication
 * tag (integrity) in a single pass. CBC provides no integrity of its own —
 * an attacker can flip ciphertext bits and the decryptor would have no idea.
 * With GCM, any bit change anywhere (nonce, ciphertext, tag, or the AAD)
 * makes tag verification fail and decryption <em>throws</em>.
 *
 * <h2>Nonce rules (the classic footgun)</h2>
 * A fresh random 96-bit (12-byte) nonce is generated for <strong>every</strong>
 * encryption. Under GCM, reusing a (key, nonce) pair is catastrophic: it
 * reveals the XOR of the two plaintexts and eventually leaks the
 * authentication key. Random 96-bit nonces are safe for ~2^32 encryptions
 * under one key (the standard's birthday bound).
 *
 * <h2>Representation decision (spec §5)</h2>
 * CipherLab's API exposes <b>separated {@code ciphertext} and {@code tag}
 * fields</b> so learners can inspect and tamper with each independently.
 * On the wire, the JCA convention applies: {@code doFinal} output is
 * {@code ciphertext || tag}. {@link #split} and {@link #join} are the only
 * places that boundary is touched.
 *
 * <p>This class is backend <b>lab</b> cryptography. It must never be fed a
 * key that the secure messaging channel uses.
 */
@Component
public class AesGcmService {

    /** GCM with no padding — the only legal transform for AES-GCM in JCA. */
    public static final String TRANSFORMATION = "AES/GCM/NoPadding";
    /** AES-256: 256-bit keys. */
    public static final int KEY_BYTES = 32;
    /** 96-bit nonce — the only nonce size GCM is specified and optimized for. */
    public static final int NONCE_BYTES = 12;
    /** 128-bit authentication tag: truncating tags weakens forgery resistance. */
    public static final int TAG_BYTES = 16;
    /** Tag length in bits, as required by {@link GCMParameterSpec}. */
    public static final int TAG_BITS = TAG_BYTES * 8;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Result of a lab encryption.
     *
     * @param nonce     fresh 12-byte IV (Base64 at the API layer)
     * @param ciphertext plaintext without the tag
     * @param tag       16-byte GCM authentication tag
     */
    public record EncryptedPayload(byte[] nonce, byte[] ciphertext, byte[] tag) {}

    /** Generates a cryptographically secure AES-256 key (32 random bytes). */
    public byte[] generateKey() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Encrypts plaintext bytes under AES-256-GCM with a fresh random nonce.
     *
     * @param key       32-byte key
     * @param plaintext data to encrypt (may be empty — GCM still emits a valid tag)
     * @param aad       associated data: authenticated but not encrypted
     *                  (e.g. message metadata), may be {@code null}
     */
    public EncryptedPayload encrypt(byte[] key, byte[] plaintext, byte[] aad) {
        requireKey(key);
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        try {
            Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, key, nonce);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] sealed = cipher.doFinal(plaintext); // output: ciphertext || tag
            byte[][] parts = split(sealed);
            return new EncryptedPayload(nonce, parts[0], parts[1]);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts and <em>authenticates</em> in one operation.
     *
     * <p><b>Security contract:</b> if any input bit was modified, JCA throws
     * {@link javax.crypto.AEADBadTagException} and <em>no plaintext is
     * produced</em>. Never catch it and continue with partial output — that
     * would turn authenticated encryption back into unauthenticated
     * decryption.
     *
     * @throws AuthenticationFailedException when the tag does not verify
     *         (tampered ciphertext, wrong key, wrong nonce, or wrong AAD)
     */
    public byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad) {
        requireKey(key);
        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("GCM nonce must be exactly 12 bytes");
        }
        if (tag == null || tag.length != TAG_BYTES) {
            throw new IllegalArgumentException("GCM tag must be exactly 16 bytes");
        }
        try {
            Cipher cipher = newCipher(Cipher.DECRYPT_MODE, key, nonce);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(join(ciphertext, tag)); // authenticates BEFORE returning plaintext
        } catch (javax.crypto.AEADBadTagException e) {
            throw new AuthenticationFailedException(e);
        } catch (GeneralSecurityException e) {
            // Malformed input shapes (e.g. sealed output too short for one tag block).
            throw new IllegalArgumentException("Malformed ciphertext input", e);
        }
    }

    /**
     * Configures a GCM cipher for the given key + 96-bit nonce.
     *
     * <p><b>The mode matters:</b> GCM decryption only performs tag
     * verification when the cipher is initialized with {@code DECRYPT_MODE}.
     * Initializing with {@code ENCRYPT_MODE} and calling {@code doFinal} on
     * ciphertext silently <em>re-encrypts</em> the bytes (appending a fresh
     * tag) — no authentication happens at all.
     */
    private static Cipher newCipher(int mode, byte[] key, byte[] nonce) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        return cipher;
    }

    /** Splits JCA's {@code ciphertext || tag} output into the two API fields. */
    static byte[][] split(byte[] sealed) {
        if (sealed.length < TAG_BYTES) {
            throw new IllegalArgumentException("Sealed output shorter than GCM tag");
        }
        int cut = sealed.length - TAG_BYTES;
        return new byte[][] {
                Arrays.copyOfRange(sealed, 0, cut),
                Arrays.copyOfRange(sealed, cut, sealed.length)
        };
    }

    /** Concatenates the two API fields back into {@code ciphertext || tag}. */
    public static byte[] join(byte[] ciphertext, byte[] tag) {
        byte[] sealed = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, sealed, 0, ciphertext.length);
        System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);
        return sealed;
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes");
        }
    }
}