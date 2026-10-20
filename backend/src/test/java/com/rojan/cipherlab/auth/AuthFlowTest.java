package com.rojan.cipherlab.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Full auth flow over the real security filter chain: register → login →
 * authenticated /me, plus the negative paths (duplicate identity, wrong
 * password, missing/expired/garbage tokens).
 *
 * <p>These tests use <em>real</em> tokens issued by the running service, not
 * test doubles — proving the whole JWT pipeline end to end.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class AuthFlowTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    /** Unique-per-run identity so tests never collide on shared H2 state. */
    private String uniqueUsername(String base) {
        return base + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private JsonNode register(String username, String password) throws Exception {
        return postJson("/api/v1/auth/register",
                "{\"username\":\"" + username + "\",\"email\":\"" + username + "@example.com\""
                        + ",\"password\":\"" + password + "\"}",
                status().isCreated());
    }

    private String login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    @Test
    @DisplayName("Register → login → /me roundtrip with a real JWT")
    void fullAuthFlow() throws Exception {
        String username = uniqueUsername("alice");
        register(username, "correct horse battery");

        String token = login(username, "correct horse battery");

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(username + "@example.com"));
    }

    @Test
    @DisplayName("Register returns 409 DUPLICATE_USERNAME for a taken name")
    void duplicateUsernameRejected() throws Exception {
        String username = uniqueUsername("bob");
        register(username, "correct horse battery");

        postJson("/api/v1/auth/register",
                "{\"username\":\"" + username + "\",\"email\":\"other@example.com\""
                        + ",\"password\":\"correct horse battery\"}",
                status().isConflict(),
                jsonPath("$.code").value("DUPLICATE_USERNAME"));
    }

    @Test
    @DisplayName("Register returns 409 DUPLICATE_EMAIL for a taken email")
    void duplicateEmailRejected() throws Exception {
        String username = uniqueUsername("carol");
        String email = uniqueUsername("carol-mail") + "@example.com";
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"email\":\"" + email
                                + "\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isCreated());

        postJson("/api/v1/auth/register",
                "{\"username\":\"" + uniqueUsername("carol2") + "\",\"email\":\"" + email
                        + "\",\"password\":\"correct horse battery\"}",
                status().isConflict(),
                jsonPath("$.code").value("DUPLICATE_EMAIL"));
    }

    @Test
    @DisplayName("Register rejects short passwords and malformed emails with INVALID_REQUEST")
    void registerValidation() throws Exception {
        postJson("/api/v1/auth/register",
                "{\"username\":\"x\",\"email\":\"not-an-email\",\"password\":\"short\"}",
                status().isBadRequest(),
                jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("Login with a wrong password returns 401 INVALID_CREDENTIALS (no username oracle)")
    void wrongPasswordRejected() throws Exception {
        String username = uniqueUsername("dave");
        register(username, "correct horse battery");

        postJson("/api/v1/auth/login",
                "{\"username\":\"" + username + "\",\"password\":\"wrong password\"}",
                status().isUnauthorized(),
                jsonPath("$.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    @DisplayName("Login with an unknown username returns the same 401 body as a wrong password")
    void unknownUserSameErrorAsWrongPassword() throws Exception {
        postJson("/api/v1/auth/login",
                "{\"username\":\"nobody-here\",\"password\":\"whatever\"}",
                status().isUnauthorized(),
                jsonPath("$.code").value("INVALID_CREDENTIALS"),
                jsonPath("$.message").value("Invalid username or password."));
    }

    @Test
    @DisplayName("The password hash never appears in any auth response")
    void passwordHashNeverLeaks() throws Exception {
        String username = uniqueUsername("erin");
        String body = register(username, "correct horse battery").toString();
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("$2a$"),
                "register response leaked a BCrypt prefix: " + body);
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("passwordHash"));

        MvcResult me = mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + login(username, "correct horse battery")))
                .andExpect(status().isOk())
                .andReturn();
        String meBody = me.getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertFalse(meBody.contains("$2a$"));
        org.junit.jupiter.api.Assertions.assertFalse(meBody.contains("passwordHash"));
    }

    @Test
    @DisplayName("Protected route without a token returns 401 UNAUTHENTICATED JSON")
    void protectedRouteWithoutToken() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("A garbage bearer token is rejected with 401, not a 500")
    void garbageTokenRejected() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer complete-garbage"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("A forged alg=none token is rejected with 401")
    void algNoneTokenRejectedOverHttp() throws Exception {
        String payload = Base64Url("{\"sub\":\"" + UUID.randomUUID()
                + "\",\"username\":\"mallory\",\"iat\":1,\"exp\":9999999999}");
        String header = Base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + header + "." + payload + "."))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("An expired token is rejected with 401")
    void expiredTokenRejectedOverHttp() throws Exception {
        String username = uniqueUsername("frank");
        register(username, "correct horse battery");
        String token = login(username, "correct horse battery");
        // A valid token works…
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        // …and the same token shape with an exp in the past does not.
        String[] parts = token.split("\\.");
        JsonNode claims = objectMapper.readTree(
                new String(java.util.Base64.getUrlDecoder().decode(parts[1]),
                        java.nio.charset.StandardCharsets.UTF_8));
        String expired = parts[0] + "." + Base64Url(
                "{\"sub\":\"" + claims.get("sub").asText() + "\",\"username\":\"" + username
                        + "\",\"iat\":1,\"exp\":2}") + "." + parts[2];
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------ helpers

    private JsonNode postJson(String path, String body,
                              org.springframework.test.web.servlet.ResultMatcher... expects) throws Exception {
        var request = mockMvc.perform(post(path)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body));
        for (org.springframework.test.web.servlet.ResultMatcher expect : expects) {
            request.andExpect(expect);
        }
        MvcResult result = request.andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private static String Base64Url(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
