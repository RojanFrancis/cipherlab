package com.rojan.cipherlab.common;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import com.rojan.cipherlab.messaging.SessionTranscript;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import tools.jackson.databind.ObjectMapper;

/**
 * The audit trail (spec §8) must record the security-relevant events —
 * registration, login, and especially replay <em>attempts</em>, which are
 * the events an operator most needs to see and which no other table
 * captures.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class AuditTrailTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    AuditEventRepository auditEventRepository;

    @Autowired
    ExperimentRepository experimentRepository;

    private String registerAndLogin(String username) throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"email\":\"" + username
                                + "@example.com\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isCreated());
        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    // ------------------------------------------- handshake helpers (same as the browser does)

    private static KeyPair newP256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static String spkiOf(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }

    private static String sign(PrivateKey privateKey, String transcript) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(transcript.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private String publishIdentityKey(String token, KeyPair pair) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + spkiOf(pair) + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText();
    }

    @Test
    @DisplayName("Registration and successful login each write an audit event")
    void authEventsAudited() throws Exception {
        String username = "audit-" + UUID.randomUUID().toString().substring(0, 8);
        long before = auditEventRepository.count();
        registerAndLogin(username);

        List<AuditEvent> events = auditEventRepository.findAll();
        org.junit.jupiter.api.Assertions.assertTrue(events.size() > before,
                "expected new audit rows");
        org.junit.jupiter.api.Assertions.assertTrue(
                events.stream().anyMatch(e -> "USER_REGISTERED".equals(e.getEventType())),
                "missing USER_REGISTERED");
        org.junit.jupiter.api.Assertions.assertTrue(
                events.stream().anyMatch(e -> "LOGIN_SUCCEEDED".equals(e.getEventType())),
                "missing LOGIN_SUCCEEDED");
    }

    @Test
    @DisplayName("A rejected replay is audited as REPLAY_REJECTED — the attempt itself is the signal")
    void replayAttemptAudited() throws Exception {
        String username = "audit-" + UUID.randomUUID().toString().substring(0, 8);
        String token = registerAndLogin(username);

        // Minimal path to a relayed message: register a partner, open a
        // conversation, create + activate a session, send, replay.
        String partner = "auditp-" + UUID.randomUUID().toString().substring(0, 8);
        MvcResult reg = mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + partner + "\",\"email\":\"" + partner
                                + "@example.com\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String partnerId = objectMapper.readTree(reg.getResponse().getContentAsString()).get("id").asText();
        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + partner + "\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String partnerToken = objectMapper.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asText();

        MvcResult conv = mockMvc.perform(post("/api/v1/conversations")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"partnerId\":\"" + partnerId + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String conversationId = objectMapper.readTree(conv.getResponse().getContentAsString())
                .get("id").asText();

        // The owner's user id (needed for the canonical transcript).
        MvcResult me = mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        String ownerId = objectMapper.readTree(me.getResponse().getContentAsString()).get("id").asText();

        // Real handshake: both sides publish identity keys and sign the transcript.
        KeyPair ownerKeys = newP256();
        String ownerKeyId = publishIdentityKey(token, ownerKeys);
        KeyPair partnerKeys = newP256();
        String partnerKeyId = publishIdentityKey(partnerToken, partnerKeys);

        UUID sessionId = UUID.randomUUID();
        String ephA = spkiOf(newP256());
        String transcriptA = SessionTranscript.initiatorForm(sessionId, UUID.fromString(conversationId),
                UUID.fromString(ownerId), UUID.fromString(partnerId), SessionTranscript.SUITE, ephA);
        mockMvc.perform(post("/api/v1/conversations/" + conversationId + "/sessions")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + ephA + "\",\"signature\":\""
                                + sign(ownerKeys.getPrivate(), transcriptA)
                                + "\",\"identityKeyId\":\"" + ownerKeyId + "\"}"))
                .andExpect(status().isCreated());

        String ephB = spkiOf(newP256());
        String transcriptFull = SessionTranscript.fullForm(sessionId, UUID.fromString(conversationId),
                UUID.fromString(ownerId), UUID.fromString(partnerId), SessionTranscript.SUITE, ephA, ephB);
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/activate")
                        .header("Authorization", "Bearer " + partnerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ephemeralPublic\":\"" + ephB + "\",\"signature\":\""
                                + sign(partnerKeys.getPrivate(), transcriptFull)
                                + "\",\"identityKeyId\":\"" + partnerKeyId + "\"}"))
                .andExpect(status().isOk());

        String envelope = "{\"sequenceNumber\":3,\"nonce\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\""
                + Base64.getEncoder().encodeToString(new byte[32]) + "\"}";
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope))
                .andExpect(status().isBadRequest());

        org.junit.jupiter.api.Assertions.assertTrue(
                auditEventRepository.findAll().stream()
                        .anyMatch(e -> "REPLAY_REJECTED".equals(e.getEventType())),
                "a replay attempt must leave an audit row even though the message was rejected");
    }

    @Test
    @DisplayName("Audit rows never carry secrets — only ids, event types and timestamps")
    void auditRowsCarryNoSecrets() throws Exception {
        String username = "auditn-" + UUID.randomUUID().toString().substring(0, 8);
        registerAndLogin(username);

        for (AuditEvent event : auditEventRepository.findAll()) {
            String blob = event.getEventType() + event.getResourceId();
            org.junit.jupiter.api.Assertions.assertFalse(blob.contains("eyJ"), // JWT prefix
                    "audit row looks like it carries a token: " + blob);
            org.junit.jupiter.api.Assertions.assertFalse(blob.contains("$2a$"),
                    "audit row looks like it carries a password hash");
        }
    }
}
