package com.rojan.cipherlab.common;

/**
 * A well-formed request that violates a lab constraint (bad lengths,
 * out-of-bounds DH parameters, unsupported algorithms). Carries an
 * machine-readable {@code code} for the standard error body.
 */
public class InvalidRequestException extends RuntimeException {

    private final String code;

    public InvalidRequestException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}