package com.rojan.cipherlab.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Reads {@code Authorization: Bearer <jwt>}, verifies it with
 * {@link JwtService}, and — only on success — populates the security
 * context.
 *
 * <p>Fail-closed by design: a missing, malformed, tampered or expired token
 * simply leaves the request unauthenticated; the filter never throws, so
 * protected routes fall through to the 401 entry point and public routes
 * (lab, register, login) keep working without a token.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            JwtService.Claims claims = jwtService.verify(header.substring(BEARER_PREFIX.length()));
            if (claims != null) {
                AuthenticatedUser principal = new AuthenticatedUser(claims.userId(), claims.username());
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        principal, null,
                        java.util.List.of(new SimpleGrantedAuthority("ROLE_USER")));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                // Presented but rejected: stay anonymous; the entry point
                // will answer 401 if this route requires authentication.
                log.debug("Rejected bearer token on {}", request.getRequestURI());
            }
        }
        filterChain.doFilter(request, response);
    }
}
