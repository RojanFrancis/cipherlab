package com.rojan.cipherlab.common;

/**
 * Ciphertext failed GCM tag verification (tamper, wrong key, or wrong AAD).
 * Mapped to HTTP 400 / {@code INVALID_CIPHERTEXT} with no plaintext disclosure.
 */
public class AuthenticationFailedException extends RuntimeException {

    public static final String DEFAULT_MESSAGE = "The ciphertext could not be authenticated.";

    public AuthenticationFailedException(Throwable cause) {
        super(DEFAULT_MESSAGE, cause);
    }
}