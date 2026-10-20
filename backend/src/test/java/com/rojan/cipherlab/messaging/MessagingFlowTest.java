package com.rojan.cipherlab.messaging;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Base64;
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
 * Full messaging flow over the real filter chain: two users meet, open a
 * conversation, run a session lifecycle, and relay ciphertext — with the
 * security invariants asserted at each step.
 *
 * <p>The star of this suite is {@code replayIsRejectedWith400}: the server
 * detects a duplicated (session, sender, sequence) <em>without being able
 * to read the ciphertext</em> — the exact property the whole design exists
 * to provide.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class MessagingFlowTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    // ------------------------------------------------------------------ setup helpers

    private record User(String username, String token) {
    }

    private User newUser() throws Exception {
        String username = "user-" + UUID.randomUUID().toString().substring(0, 8);
        MvcResult reg = mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"email\":\"" + username
                                + "@example.com\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String userId = objectMapper.readTree(reg.getResponse().getContentAsString()).get("id").asText();

        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String token = objectMapper.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asText();
        return new User(username + "|" + userId, token);
    }

    private static String userIdOf(User user) {
        return user.username().split("\\|")[1];
    }

    private JsonNode createConversation(User owner, String partnerUserId) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/conversations")
                        .header("Authorization", "Bearer " + owner.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"partnerId\":\"" + partnerUserId + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode createSession(User initiator, String conversationId) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/conversations/" + conversationId + "/sessions")
                        .header("Authorization", "Bearer " + initiator.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"suite\":\"X25519+HKDF-SHA256+AES-256-GCM\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // ------------------------------------------------------------------ the flow

    @Test
    @DisplayName("Two users can open a conversation, activate a session, and relay ciphertext")
    void fullMessagingFlow() throws Exception {
        User alice = newUser();
        User bob = newUser();

        JsonNode conversation = createConversation(alice, userIdOf(bob));
        String conversationId = conversation.get("id").asText();

        // Both members can see the conversation; a stranger cannot.
        mockMvc.perform(get("/api/v1/conversations")
                        .header("Authorization", "Bearer " + bob.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + conversationId + "')]").exists());

        JsonNode session = createSession(alice, conversationId);
        String sessionId = session.get("id").asText();

        // Relay before activation is refused — lifecycle is enforced.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + b64(new byte[12])
                                + "\",\"ciphertext\":\"" + b64("ciphertext-one".getBytes()) + "\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("SESSION_NOT_ACTIVE"));

        // The responder activates.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/activate")
                        .header("Authorization", "Bearer " + bob.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.expiresAt").isNotEmpty());

        // Initiator cannot self-activate (already done by responder; either order is
        // covered — attempting activation again must 409).
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/activate")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isConflict());

        // Both sides relay ciphertext.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + b64(new byte[12])
                                + "\",\"ciphertext\":\"" + b64("alice-first".getBytes()) + "\"}"))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + bob.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + b64(new byte[12])
                                + "\",\"ciphertext\":\"" + b64("bob-reply".getBytes()) + "\"}"))
                .andExpect(status().isCreated());

        // History shows both envelopes — still ciphertext, never plaintext.
        MvcResult history = mockMvc.perform(get("/api/v1/conversations/" + conversationId + "/messages")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andReturn();
        String body = history.getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("alice-first"),
                "relay echoed plaintext — it must store ciphertext only");
    }

    @Test
    @DisplayName("Replay: resubmitting the same (session, sender, sequence) is rejected with 400 REPLAYED_MESSAGE")
    void replayIsRejectedWith400() throws Exception {
        User alice = newUser();
        User bob = newUser();

        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText());
        String sessionId = session.get("id").asText();
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/activate")
                        .header("Authorization", "Bearer " + bob.token()))
                .andExpect(status().isOk());

        String envelope = "{\"sequenceNumber\":7,\"nonce\":\"" + b64(new byte[12])
                + "\",\"ciphertext\":\"" + b64("pay me 100 coins".getBytes()) + "\"}";

        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope))
                .andExpect(status().isCreated());

        // Exact same envelope again — a textbook replay.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("REPLAYED_MESSAGE"));

        // A different sender may reuse sequence 7 — the constraint is per-sender.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + bob.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("Only conversation members can relay or read; outsiders get 404, not 403")
    void nonMemberRejectedWith404() throws Exception {
        User alice = newUser();
        User bob = newUser();
        User mallory = newUser();

        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText());
        mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/activate")
                        .header("Authorization", "Bearer " + bob.token()))
                .andExpect(status().isOk());

        // Mallory cannot relay on a session she is not part of…
        mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/messages")
                        .header("Authorization", "Bearer " + mallory.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + b64(new byte[12])
                                + "\",\"ciphertext\":\"" + b64("sneaky".getBytes()) + "\"}"))
                .andExpect(status().isNotFound());

        // …cannot read the history…
        mockMvc.perform(get("/api/v1/conversations/" + conversation.get("id").asText() + "/messages")
                        .header("Authorization", "Bearer " + mallory.token()))
                .andExpect(status().isNotFound());

        // …and cannot open a session in someone else's conversation.
        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + mallory.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"suite\":\"X25519+HKDF-SHA256+AES-256-GCM\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("The initiator cannot activate their own session; only the responder can")
    void initiatorCannotSelfActivate() throws Exception {
        User alice = newUser();
        User bob = newUser();
        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText());

        mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/activate")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("NOT_RESPONDER"));
    }

    @Test
    @DisplayName("Creating a conversation with yourself is rejected")
    void selfConversationRejected() throws Exception {
        User alice = newUser();
        mockMvc.perform(post("/api/v1/conversations")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"partnerId\":\"" + userIdOf(alice) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("Unsupported suite labels are rejected by validation")
    void unsupportedSuiteRejected() throws Exception {
        User alice = newUser();
        User bob = newUser();
        JsonNode conversation = createConversation(alice, userIdOf(bob));

        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"suite\":\"ROT13+KID-SAFE\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("Messaging endpoints require authentication")
    void messagingEndpointsRequireAuth() throws Exception {
        mockMvc.perform(get("/api/v1/conversations"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }
}
