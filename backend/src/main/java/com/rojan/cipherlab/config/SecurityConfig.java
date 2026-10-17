package com.rojan.cipherlab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Day 1 + lab security configuration.
 *
 * <p>Three zones:
 * <ul>
 *   <li><b>Public liveness:</b> {@code /actuator/health} — probes only.</li>
 *   <li><b>Public lab:</b> {@code /api/v1/lab/**} — stateless educational
 *       demonstrations that hold no user data (these must never perform
 *       operations on real user keys or ciphertext).</li>
 *   <li><b>Authenticated:</b> everything else — identity keys, conversations,
 *       message relay (JWT bearer wiring lands in Week 3).</li>
 * </ul>
 *
 * <p>The API is stateless (no HTTP session, CSRF disabled) because clients
 * authenticate per request.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/api/v1/lab/**").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}