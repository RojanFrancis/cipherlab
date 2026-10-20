package com.rojan.cipherlab.config;

import java.util.List;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.SecurityFilterChain;

import com.rojan.cipherlab.security.AuthenticatedUser;
import com.rojan.cipherlab.security.JwtService;
import com.rojan.cipherlab.security.SecurityErrorResponses;

/**
 * Stateless JWT security configuration built on Spring Security's standard
 * <b>OAuth2 resource server</b>: bearer tokens are verified by the
 * {@link JwtDecoder} bean below (Nimbus — signature, issuer, expiry), not by
 * any bespoke parsing code. Custom {@code JwtAuthenticationFilter} was
 * removed; the only customization left is mapping verified claims onto this
 * application's {@link AuthenticatedUser} principal.
 *
 * <p>Three zones (spec §6):
 * <ul>
 *   <li><b>Public liveness:</b> {@code /actuator/health} — probes only.</li>
 *   <li><b>Public lab + auth bootstrap:</b> {@code /api/v1/lab/**} holds no
 *       user data; {@code /api/v1/auth/register} and {@code /login} are the
 *       only ways to obtain a token, so they must be reachable
 *       anonymously.</li>
 *   <li><b>Authenticated:</b> everything else — identity keys, handshake,
 *       ciphertext relay. The resource-server filter verifies the Bearer
 *       token per request; no HTTP session exists at all.</li>
 * </ul>
 *
 * <p>CSRF is disabled because there are no cookies: the token travels in the
 * {@code Authorization} header of each request, which cross-site forms and
 * images cannot set — the classic CSRF vector is absent by construction.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final SecurityErrorResponses.BearerAuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityErrorResponses.JsonAccessDeniedHandler accessDeniedHandler;

    public SecurityConfig(SecurityErrorResponses.BearerAuthenticationEntryPoint authenticationEntryPoint,
                          SecurityErrorResponses.JsonAccessDeniedHandler accessDeniedHandler) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    /**
     * Standard decoder: HS256 signature + timestamp + issuer validation. The
     * secret policy (fail-fast, dev-default rejection) is enforced by
     * {@link JwtService}, whose instance method builds this exact decoder so
     * tests exercise the same construction.
     */
    @Bean
    JwtDecoder jwtDecoder(JwtService jwtService) {
        return jwtService.createDecoder();
    }

    /**
     * Maps a verified JWT onto {@link AuthenticatedUser} — identity only.
     * A token whose {@code sub} is not a UUID is rejected outright rather
     * than authenticated with a broken principal.
     */
    static Converter<Jwt, AbstractAuthenticationToken> authenticationConverter() {
        return jwt -> {
            UUID userId;
            try {
                userId = UUID.fromString(jwt.getSubject());
            } catch (RuntimeException e) {
                throw new InvalidBearerTokenException("Token subject is not a valid user id");
            }
            String username = jwt.getClaim("username");
            AuthenticatedUser principal = new AuthenticatedUser(userId, username);
            return new UsernamePasswordAuthenticationToken(
                    principal, jwt.getTokenValue(),
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
        };
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/api/v1/lab/**").permitAll()
                        .requestMatchers("/api/v1/auth/register", "/api/v1/auth/login").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter()))
                        .authenticationEntryPoint(authenticationEntryPoint))
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }
}
