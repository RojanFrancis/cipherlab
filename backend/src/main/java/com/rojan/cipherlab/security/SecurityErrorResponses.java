package com.rojan.cipherlab.security;

import java.io.IOException;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import tools.jackson.databind.ObjectMapper;

import com.rojan.cipherlab.common.ApiError;

/**
 * Keeps 401/403 responses on the same {@code {code, message, traceId}}
 * contract as every other error. These are produced by the security filter
 * chain <em>before</em> any controller runs, so the MVC exception advice
 * never sees them — the contract needs handlers here too.
 */
public final class SecurityErrorResponses {

    private SecurityErrorResponses() {
    }

    /** 401: no (or rejected) credentials on a protected route. */
    @Component
    public static class BearerAuthenticationEntryPoint implements AuthenticationEntryPoint {
        private final ObjectMapper objectMapper = new ObjectMapper();

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationException authException) throws IOException {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            objectMapper.writeValue(response.getOutputStream(),
                    new ApiError("UNAUTHENTICATED",
                            "A valid Bearer token is required for this endpoint", traceId()));
        }
    }

    /** 403: authenticated, but not allowed (e.g. not a conversation member). */
    @Component
    public static class JsonAccessDeniedHandler implements AccessDeniedHandler {
        private final ObjectMapper objectMapper = new ObjectMapper();

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response,
                           AccessDeniedException accessDeniedException) throws IOException {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            objectMapper.writeValue(response.getOutputStream(),
                    new ApiError("FORBIDDEN",
                            "You do not have access to this resource", traceId()));
        }
    }

    private static String traceId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }
}
