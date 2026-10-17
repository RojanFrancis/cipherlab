package com.rojan.cipherlab.lab;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Base64;

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
 * End-to-end verification of the lab API contract over the real MVC stack
 * (security filter chain + validation + controllers + advice — not just
 * service unit tests).
 *
 * <p>Covers the spec's minimum security tests relevant to Week 1:
 * AES-GCM tampering rejection, HMAC/signature-adjacent primitives, malformed
 * input rejection, and the authentication boundary of non-lab routes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class LabControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    // ------------------------------------------------------------------
    // AES-GCM over HTTP
    // ------------------------------------------------------------------

    @Test
    @DisplayName("HTTP encrypt → decrypt roundtrip returns the original plaintext with authenticated=true")
    void encryptDecryptRoundTrip() throws Exception {
        JsonNode enc = postJson("/api/v1/lab/aes/encrypt",
                "{\"plaintext\":\"hello cipherlab 123\"}", status().isOk());

        JsonNode dec = postJson("/api/v1/lab/aes/decrypt",
                "{\"key\":\"" + enc.get("key").asText() + "\""
                        + ",\"nonce\":\"" + enc.get("nonce").asText() + "\""
                        + ",\"ciphertext\":\"" + enc.get("ciphertext").asText() + "\""
                        + ",\"tag\":\"" + enc.get("tag").asText() + "\"}",
                status().isOk());

        org.junit.jupiter.api.Assertions.assertEquals("hello cipherlab 123", dec.get("plaintext").asText());
        org.junit.jupiter.api.Assertions.assertTrue(dec.get("authenticated").asBoolean());
        org.junit.jupiter.api.Assertions.assertEquals("AES/GCM/NoPadding", enc.get("algorithm").asText());
        // separated fields AND their wire-form combination must agree
        byte[] wire = Base64.getDecoder().decode(enc.get("combined").asText());
        byte[] ct = Base64.getDecoder().decode(enc.get("ciphertext").asText());
        byte[] tag = Base64.getDecoder().decode(enc.get("tag").asText());
        org.junit.jupiter.api.Assertions.assertEquals(ct.length + tag.length, wire.length);
    }

    @Test
    @DisplayName("SPEC: one flipped ciphertext bit over HTTP → 400 INVALID_CIPHERTEXT, never plaintext")
    void tamperedCiphertextRejectedOverHttp() throws Exception {
        JsonNode enc = postJson("/api/v1/lab/aes/encrypt",
                "{\"plaintext\":\"top secret lab note\"}", status().isOk());

        byte[] ct = Base64.getDecoder().decode(enc.get("ciphertext").asText());
        ct[0] ^= 0x40;

        mockMvc.perform(post("/api/v1/lab/aes/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"key\":\"" + enc.get("key").asText() + "\""
                                + ",\"nonce\":\"" + enc.get("nonce").asText() + "\""
                                + ",\"ciphertext\":\"" + Base64.getEncoder().encodeToString(ct) + "\""
                                + ",\"tag\":\"" + enc.get("tag").asText() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CIPHERTEXT"))
                .andExpect(jsonPath("$.message").value("The ciphertext could not be authenticated."))
                .andExpect(jsonPath("$.traceId").isNotEmpty())
                .andExpect(jsonPath("$.plaintext").doesNotExist());
    }

    @Test
    @DisplayName("wrong key length rejected before reaching JCA (clean 400, no 500)")
    void wrongKeyLengthRejected() throws Exception {
        mockMvc.perform(post("/api/v1/lab/aes/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"key\":\"" + Base64.getEncoder().encodeToString(new byte[16]) + "\""
                                + ",\"nonce\":\"" + Base64.getEncoder().encodeToString(new byte[12]) + "\""
                                + ",\"ciphertext\":\"YWJj\""
                                + ",\"tag\":\"" + Base64.getEncoder().encodeToString(new byte[16]) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_LENGTH"));
    }

    @Test
    @DisplayName("blank plaintext fails Bean Validation with 400 INVALID_REQUEST")
    void blankPlaintextRejected() throws Exception {
        mockMvc.perform(post("/api/v1/lab/aes/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"  \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("malformed JSON body → 400 MALFORMED_REQUEST")
    void malformedJsonRejected() throws Exception {
        mockMvc.perform(post("/api/v1/lab/hash")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }

    // ------------------------------------------------------------------
    // Hashing / HMAC over HTTP
    // ------------------------------------------------------------------

    @Test
    @DisplayName("SHA-256 endpoint returns the NIST vector")
    void hashOverHttp() throws Exception {
        mockMvc.perform(post("/api/v1/lab/hash")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"abc\",\"algorithm\":\"SHA-256\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.digest")
                        .value("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    @Test
    @DisplayName("unsupported algorithm → 400 with code")
    void unsupportedAlgorithmRejected() throws Exception {
        mockMvc.perform(post("/api/v1/lab/hash")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"x\",\"algorithm\":\"MD5\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("UNSUPPORTED_ALGORITHM"));
    }

    // ------------------------------------------------------------------
    // Toy Diffie–Hellman over HTTP + bound enforcement
    // ------------------------------------------------------------------

    @Test
    @DisplayName("toy DH endpoint: both parties agree on the shared secret, steps exposed")
    void diffieHellmanOverHttp() throws Exception {
        mockMvc.perform(post("/api/v1/lab/diffie-hellman")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"p\":\"23\",\"g\":\"5\",\"alicePrivate\":\"6\",\"bobPrivate\":\"15\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alicePublic").value("8"))
                .andExpect(jsonPath("$.bobPublic").value("19"))
                .andExpect(jsonPath("$.sharedSecret").value("2"))
                .andExpect(jsonPath("$.steps").isArray());
    }

    @Test
    @DisplayName("DH inputs beyond lab bounds → 400 INVALID_DH_PARAMETERS")
    void dhBoundEnforcedOverHttp() throws Exception {
        // 160 digits ≈ 528 bits — passes the DTO's \d{1,160} shape check,
        // then trips the service's 512-bit CPU-exhaustion bound.
        mockMvc.perform(post("/api/v1/lab/diffie-hellman")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"p\":\"" + "2".repeat(160) + "\",\"g\":\"5\","
                                + "\"alicePrivate\":\"6\",\"bobPrivate\":\"15\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_DH_PARAMETERS"));
    }

    // ------------------------------------------------------------------
    // Authentication boundary
    // ------------------------------------------------------------------

    @Test
    @DisplayName("lab routes are public, every other route still demands authentication")
    void labPublicButRestProtected() throws Exception {
        mockMvc.perform(post("/api/v1/lab/hmac")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"Hi\",\"key\":\"k\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("HmacSHA256"));

        mockMvc.perform(get("/api/v1/keys/someone"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/conversations"))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------

    /** POSTs JSON and returns the parsed body after asserting the expected result matcher. */
    private JsonNode postJson(String url, String body,
            org.springframework.test.web.servlet.ResultMatcher expect) throws Exception {
        MvcResult result = mockMvc.perform(post(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(expect)
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }
}