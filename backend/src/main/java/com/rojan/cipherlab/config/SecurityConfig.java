package com.rojan.cipherlab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.rojan.cipherlab.security.JwtAuthenticationFilter;
import com.rojan.cipherlab.security.SecurityErrorResponses;

/**
 * Stateless JWT security configuration.
 *
 * <p>Three zones (spec §6):
 * <ul>
 *   <li><b>Public liveness:</b> {@code /actuator/health} — probes only.</li>
 *   <li><b>Public lab + auth bootstrap:</b> {@code /api/v1/lab/**} holds no
 *       user data; {@code /api/v1/auth/register} and {@code /login} are the
 *       only ways to obtain a token, so they must be reachable
 *       anonymously.</li>
 *   <li><b>Authenticated:</b> everything else — identity keys, sessions,
 *       ciphertext relay. The {@link JwtAuthenticationFilter} verifies the
 *       Bearer token per request; no HTTP session exists at all.</li>
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

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final SecurityErrorResponses.BearerAuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityErrorResponses.JsonAccessDeniedHandler accessDeniedHandler;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          SecurityErrorResponses.BearerAuthenticationEntryPoint authenticationEntryPoint,
                          SecurityErrorResponses.JsonAccessDeniedHandler accessDeniedHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
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
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
