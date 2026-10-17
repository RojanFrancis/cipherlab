package com.rojan.cipherlab.common;

import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Single place where every error response is shaped into the spec's
 * {@code {code, message, traceId}} contract.
 *
 * <p>Rules enforced here (spec §5):
 * <ul>
 *   <li>400 for invalid requests — including AEAD authentication failures
 *       ({@code INVALID_CIPHERTEXT});</li>
 *   <li>no stack traces, secrets or plaintext ever leave the process;</li>
 *   <li>every response carries a fresh {@code traceId} for correlation.</li>
 * </ul>
 *
 * <p>401 (unauthenticated) and 403 (unauthorized) are produced by the
 * security filter chain <em>before</em> a controller runs, so they never
 * reach this advice.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private static String traceId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    /** GCM tag mismatch: tampering, wrong key, or wrong AAD. No plaintext leaks. */
    @ExceptionHandler(AuthenticationFailedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError authenticationFailed(AuthenticationFailedException ex) {
        log.info("AEAD verification rejected ciphertext: {}", ex.getMessage());
        return new ApiError("INVALID_CIPHERTEXT", AuthenticationFailedException.DEFAULT_MESSAGE, traceId());
    }

    /** Well-formed request, violated lab constraint. */
    @ExceptionHandler(InvalidRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError invalidRequest(InvalidRequestException ex) {
        return new ApiError(ex.getCode(), ex.getMessage(), traceId());
    }

    /** Bean Validation failures — first field error, compact wording. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError validationFailed(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        if (message.isEmpty()) {
            message = "Request validation failed";
        }
        return new ApiError("INVALID_REQUEST", message, traceId());
    }

    /** Unparseable JSON body. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError unreadable(HttpMessageNotReadableException ex) {
        return new ApiError("MALFORMED_REQUEST", "Request body could not be parsed as JSON", traceId());
    }

    /**
     * Last resort for unexpected runtime failures: generic message only —
     * internals stay in the logs.
     *
     * <p>Fewer MVC-internals ({@link org.springframework.web.ErrorResponse}
     * instances such as 404/405/415) are rethrown so the framework's normal
     * status handling applies instead of being relabeled 500. Checked
     * exceptions are never caught here at all.
     */
    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiError unexpected(RuntimeException ex) {
        if (ex instanceof org.springframework.web.ErrorResponse) {
            throw ex; // not ours: let DispatcherServlet produce 404/405/415
        }
        log.error("Unhandled server error", ex);
        return new ApiError("INTERNAL_ERROR", "An unexpected error occurred", traceId());
    }
}