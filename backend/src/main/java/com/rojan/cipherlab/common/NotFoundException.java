package com.rojan.cipherlab.common;

/**
 * Request referenced a resource that does not exist <em>or</em> that the
 * caller must not know exists (e.g. a conversation they are not a member
 * of). Collapsing both into 404 is deliberate: a membership probe must not
 * be able to distinguish "no such conversation" from "not yours".
 */
public class NotFoundException extends RuntimeException {

    public static final String DEFAULT_MESSAGE = "The requested resource was not found.";

    public NotFoundException() {
        super(DEFAULT_MESSAGE);
    }

    public NotFoundException(String message) {
        super(message);
    }
}
