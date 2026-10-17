package com.rojan.cipherlab.common;

/**
 * Standard API error body (spec §5):
 *
 * <pre>
 * { "code": "...", "message": "....", "traceId": "..." }
 * </pre>
 *
 * Never carries stack traces, secrets, or plaintext — the three headings of
 * "what can an attacker learn from this response" are always "nothing".
 */
public record ApiError(String code, String message, String traceId) {
}