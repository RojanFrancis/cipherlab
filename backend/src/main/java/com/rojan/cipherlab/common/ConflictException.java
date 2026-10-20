package com.rojan.cipherlab.common;

/**
 * The request is well-formed but conflicts with existing state — a taken
 * username/email, or an action on a session whose status forbids it
 * (e.g. sending on a PENDING session). Mapped to HTTP 409.
 */
public class ConflictException extends RuntimeException {

    private final String code;

    public ConflictException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
