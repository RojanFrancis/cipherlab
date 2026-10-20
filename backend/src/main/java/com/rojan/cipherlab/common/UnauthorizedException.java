package com.rojan.cipherlab.common;

/**
 * Credentials were presented but are wrong (unknown username or bad
 * password). Mapped to HTTP 401 / {@code INVALID_CREDENTIALS}.
 *
 * <p>The message is identical for both cases on purpose — a login endpoint
 * that says "no such user" vs "wrong password" hands an attacker a username
 * oracle. Registration already reveals uniqueness, but login must not
 * re-confirm it.
 */
public class UnauthorizedException extends RuntimeException {

    public static final String DEFAULT_MESSAGE = "Invalid username or password.";

    public UnauthorizedException() {
        super(DEFAULT_MESSAGE);
    }
}
