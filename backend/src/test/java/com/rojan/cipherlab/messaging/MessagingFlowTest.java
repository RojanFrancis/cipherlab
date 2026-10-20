package com.rojan.cipherlab.messaging;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
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
 * Full messaging flow over the real filter chain: two users register real
 * identity keys, complete the <b>signed ephemeral ECDH handshake</b>, relay
 * AES-GCM envelopes, and the security invariants are asserted at each step.
 *
 * <p>The handshake helpers below do exactly what the browser will do
 * (generate P-256 keys, sign the canonical transcript with the identity
 * private key), so the server-side verification path is exercised end to
 * end — including every way to get it wrong (substituted ephemerals,
 * signatures from the wrong key, revoked keys, foreign keys).
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

    /** A registered identity keypair — the client keeps the private half. */
    private record Identity(String keyId, KeyPair pair) {
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

    private static KeyPair newP256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static String spki(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }

    private static String sign(PrivateKey privateKey, String transcript) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(transcript.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private Identity publishIdentityKey(User user) throws Exception {
        KeyPair pair = newP256KeyPair();
        MvcResult result = mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + spki(pair) + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String keyId = objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText();
        return new Identity(keyId, pair);
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

    /** Initiator side of the handshake: signed ephemeral, client-chosen session id. */
    private JsonNode createSession(User initiator, String conversationId,
                                   String partnerUserId, Identity identity) throws Exception {
        return createSession(initiator, conversationId, partnerUserId, identity,
                UUID.randomUUID(), spki(newP256KeyPair()));
    }

    private JsonNode createSession(User initiator, String conversationId, String partnerUserId,
                                   Identity identity, UUID sessionId, String ephB64) throws Exception {
        String transcript = SessionTranscript.initiatorForm(sessionId, UUID.fromString(conversationId),
                UUID.fromString(userIdOf(initiator)), UUID.fromString(partnerUserId),
                SessionTranscript.SUITE, ephB64);
        String signature = sign(identity.pair().getPrivate(), transcript);
        MvcResult result = mockMvc.perform(post("/api/v1/conversations/" + conversationId + "/sessions")
                        .header("Authorization", "Bearer " + initiator.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + ephB64 + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + identity.keyId() + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    /** Responder side: verify nothing client-side here — sign the FULL transcript and activate. */
    private MvcResult activate(User responder, JsonNode session, Identity identity) throws Exception {
        return activate(responder, session, identity, spki(newP256KeyPair()));
    }

    private MvcResult activate(User responder, JsonNode session, Identity identity,
                               String responderEphB64) throws Exception {
        String transcript = SessionTranscript.fullForm(
                UUID.fromString(session.get("id").asText()),
                UUID.fromString(session.get("conversationId").asText()),
                UUID.fromString(session.get("initiatorId").asText()),
                UUID.fromString(session.get("responderId").asText()),
                SessionTranscript.SUITE,
                session.get("initiatorEphemeralPublic").asText(), responderEphB64);
        String signature = sign(identity.pair().getPrivate(), transcript);
        return mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/activate")
                        .header("Authorization", "Bearer " + responder.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ephemeralPublic\":\"" + responderEphB64 + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + identity.keyId() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.transcriptHash").isNotEmpty())
                .andReturn();
    }

    /** A structurally valid AES-GCM envelope: 12-byte nonce + ct||tag (32 bytes). */
    private static String envelope(long sequenceNumber) {
        return "{\"sequenceNumber\":" + sequenceNumber
                + ",\"nonce\":\"" + Base64.getEncoder().encodeToString(new byte[12])
                + "\",\"ciphertext\":\"" + Base64.getEncoder().encodeToString(new byte[32]) + "\"}";
    }

    // ------------------------------------------------------------------ the flow

    @Test
    @DisplayName("Two users complete the signed handshake and relay ciphertext")
    void fullMessagingFlow() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        Identity bobIdentity = publishIdentityKey(bob);

        JsonNode conversation = createConversation(alice, userIdOf(bob));
        String conversationId = conversation.get("id").asText();

        // Both members can see the conversation; a stranger cannot.
        mockMvc.perform(get("/api/v1/conversations")
                        .header("Authorization", "Bearer " + bob.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + conversationId + "')]").exists());

        JsonNode session = createSession(alice, conversationId, userIdOf(bob), aliceIdentity);
        String sessionId = session.get("id").asText();

        // The initiator's signed ephemeral is visible to the responder for client-side verification.
        mockMvc.perform(get("/api/v1/sessions/" + sessionId)
                        .header("Authorization", "Bearer " + bob.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.initiatorEphemeralPublic").isNotEmpty())
                .andExpect(jsonPath("$.initiatorSignature").isNotEmpty());

        // Relay before the handshake completes is refused — lifecycle is enforced.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope(0)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("SESSION_NOT_ACTIVE"));

        // Responder completes the handshake with their own signed ephemeral.
        activate(bob, session, bobIdentity);

        // Both sides relay envelopes.
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope(0)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + bob.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope(0)))
                .andExpect(status().isCreated());

        // History shows both envelopes — still ciphertext, never plaintext.
        MvcResult history = mockMvc.perform(get("/api/v1/conversations/" + conversationId + "/messages")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andReturn();
        String body = history.getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("plaintext"),
                "relay echoed plaintext — it must store ciphertext only");
    }

    @Test
    @DisplayName("Replay: resubmitting the same (session, sender, sequence) is rejected with 400 REPLAYED_MESSAGE")
    void replayIsRejectedWith400() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        Identity bobIdentity = publishIdentityKey(bob);

        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity);
        String sessionId = session.get("id").asText();
        activate(bob, session, bobIdentity);

        String envelope = envelope(7);

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
        Identity aliceIdentity = publishIdentityKey(alice);
        Identity bobIdentity = publishIdentityKey(bob);

        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity);
        activate(bob, session, bobIdentity);

        // Mallory cannot relay on a session she is not part of…
        mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/messages")
                        .header("Authorization", "Bearer " + mallory.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(envelope(0)))
                .andExpect(status().isNotFound());

        // …cannot read the history…
        mockMvc.perform(get("/api/v1/conversations/" + conversation.get("id").asText() + "/messages")
                        .header("Authorization", "Bearer " + mallory.token()))
                .andExpect(status().isNotFound());

        // …and cannot open a session in someone else's conversation.
        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + mallory.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + UUID.randomUUID()
                                + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + spki(newP256KeyPair())
                                + "\",\"signature\":\"bm90LWEtc2lnbmF0dXJl\",\"identityKeyId\":\"" + UUID.randomUUID() + "\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("The initiator cannot activate their own session; only the responder can")
    void initiatorCannotSelfActivate() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        Identity bobIdentity = publishIdentityKey(bob);
        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity);

        // Alice presents valid material but is not the responder — 409, checked before any crypto.
        mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/activate")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ephemeralPublic\":\"" + spki(newP256KeyPair())
                                + "\",\"signature\":\"" + "bm90LWEtc2lnbmF0dXJl"
                                + "\",\"identityKeyId\":\"" + bobIdentity.keyId() + "\"}"))
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
    @DisplayName("Unsupported suite labels are rejected — including the TOY_DH label")
    void unsupportedSuiteRejected() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        JsonNode conversation = createConversation(alice, userIdOf(bob));
        UUID sessionId = UUID.randomUUID();
        String eph = spki(newP256KeyPair());

        for (String suite : new String[] {"ROT13+KID-SAFE", "TOY_DH+HKDF-SHA256+AES-256-GCM",
                "X25519+HKDF-SHA256+AES-256-GCM"}) {
            mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                            .header("Authorization", "Bearer " + alice.token())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + suite
                                    + "\",\"ephemeralPublic\":\"" + eph
                                    + "\",\"signature\":\"bm90LWEtc2lnbmF0dXJl\",\"identityKeyId\":\""
                                    + aliceIdentity.keyId() + "\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        }
    }

    // ------------------------------------------------------------------ handshake attacks

    @Test
    @DisplayName("A signature from a different key does not verify — substituted identity key")
    void signatureFromWrongKeyRejected() throws Exception {
        User alice = newUser();
        Identity published = publishIdentityKey(alice);
        Identity otherKey = new Identity(published.keyId(), newP256KeyPair());

        User bob = newUser();
        publishIdentityKey(bob);
        JsonNode conversation = createConversation(alice, userIdOf(bob));

        // Sign the transcript with a key that is NOT the one registered under identityKeyId.
        UUID sessionId = UUID.randomUUID();
        String eph = spki(newP256KeyPair());
        String transcript = SessionTranscript.initiatorForm(sessionId,
                UUID.fromString(conversation.get("id").asText()),
                UUID.fromString(userIdOf(alice)), UUID.fromString(userIdOf(bob)),
                SessionTranscript.SUITE, eph);
        String signature = sign(otherKey.pair().getPrivate(), transcript);

        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + eph + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + published.keyId() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("HANDSHAKE_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("An ephemeral substituted after signing breaks the signature — key substitution is caught")
    void substitutedEphemeralRejected() throws Exception {
        User alice = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        User bob = newUser();
        publishIdentityKey(bob);
        JsonNode conversation = createConversation(alice, userIdOf(bob));

        UUID sessionId = UUID.randomUUID();
        String signedEph = spki(newP256KeyPair());
        String substitutedEph = spki(newP256KeyPair()); // Mallory swaps this in transit
        String transcript = SessionTranscript.initiatorForm(sessionId,
                UUID.fromString(conversation.get("id").asText()),
                UUID.fromString(userIdOf(alice)), UUID.fromString(userIdOf(bob)),
                SessionTranscript.SUITE, signedEph);
        String signature = sign(aliceIdentity.pair().getPrivate(), transcript);

        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + substitutedEph + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + aliceIdentity.keyId() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("HANDSHAKE_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("Activation with a signature over the wrong transcript is rejected")
    void responderBadSignatureRejected() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        Identity bobIdentity = publishIdentityKey(bob);
        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity);

        // Bob signs the initiator-form transcript (omitting his own ephemeral) — invalid.
        String responderEph = spki(newP256KeyPair());
        String wrongTranscript = SessionTranscript.initiatorForm(
                UUID.fromString(session.get("id").asText()),
                UUID.fromString(session.get("conversationId").asText()),
                UUID.fromString(session.get("initiatorId").asText()),
                UUID.fromString(session.get("responderId").asText()),
                SessionTranscript.SUITE,
                session.get("initiatorEphemeralPublic").asText());
        String signature = sign(bobIdentity.pair().getPrivate(), wrongTranscript);

        mockMvc.perform(post("/api/v1/sessions/" + session.get("id").asText() + "/activate")
                        .header("Authorization", "Bearer " + bob.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ephemeralPublic\":\"" + responderEph + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + bobIdentity.keyId() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("HANDSHAKE_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("Revoked or foreign identity keys cannot anchor a handshake")
    void unusableIdentityKeyRejected() throws Exception {
        User alice = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        User bob = newUser();
        Identity bobIdentity = publishIdentityKey(bob);
        JsonNode conversation = createConversation(alice, userIdOf(bob));

        // Bob's key cannot be used for Alice's handshake (foreign key).
        UUID sessionId = UUID.randomUUID();
        String eph = spki(newP256KeyPair());
        String transcript = SessionTranscript.initiatorForm(sessionId,
                UUID.fromString(conversation.get("id").asText()),
                UUID.fromString(userIdOf(alice)), UUID.fromString(userIdOf(bob)),
                SessionTranscript.SUITE, eph);
        String signature = sign(bobIdentity.pair().getPrivate(), transcript);
        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + eph + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + bobIdentity.keyId() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_IDENTITY_KEY"));

        // Alice revokes her own key — it can no longer anchor handshakes.
        mockMvc.perform(post("/api/v1/identity/keys/" + aliceIdentity.keyId() + "/revoke")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isOk());
        String signature2 = sign(aliceIdentity.pair().getPrivate(), transcript);
        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + UUID.randomUUID() + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + eph + "\",\"signature\":\"" + signature2
                                + "\",\"identityKeyId\":\"" + aliceIdentity.keyId() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_IDENTITY_KEY"));
    }

    @Test
    @DisplayName("Malformed envelopes are rejected: bad nonce size, short ciphertext, oversized body")
    void malformedEnvelopesRejected() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        Identity bobIdentity = publishIdentityKey(bob);
        JsonNode conversation = createConversation(alice, userIdOf(bob));
        JsonNode session = createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity);
        String sessionId = session.get("id").asText();
        activate(bob, session, bobIdentity);

        String goodNonce = Base64.getEncoder().encodeToString(new byte[12]);

        // 8-byte nonce (not a 96-bit GCM nonce):
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + Base64.getEncoder().encodeToString(new byte[8])
                                + "\",\"ciphertext\":\"" + Base64.getEncoder().encodeToString(new byte[32]) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_NONCE"));

        // Ciphertext shorter than the GCM tag:
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + goodNonce
                                + "\",\"ciphertext\":\"" + Base64.getEncoder().encodeToString(new byte[8]) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CIPHERTEXT"));

        // Non-Base64 nonce:
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"!!!\",\"ciphertext\":\""
                                + Base64.getEncoder().encodeToString(new byte[32]) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_NONCE"));

        // Oversized ciphertext (> 65536 chars) — rejected by request validation.
        String oversized = "A".repeat(70000);
        mockMvc.perform(post("/api/v1/sessions/" + sessionId + "/messages")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sequenceNumber\":0,\"nonce\":\"" + goodNonce
                                + "\",\"ciphertext\":\"" + oversized + "\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Duplicate client-chosen session ids are refused")
    void duplicateSessionIdRejected() throws Exception {
        User alice = newUser();
        User bob = newUser();
        Identity aliceIdentity = publishIdentityKey(alice);
        JsonNode conversation = createConversation(alice, userIdOf(bob));
        createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity);

        // Re-using ANY previously seen session id must 409 — the first call above
        // consumed a random UUID, so mint a fresh one, create, then repeat it.
        UUID sessionId = UUID.randomUUID();
        createSession(alice, conversation.get("id").asText(), userIdOf(bob), aliceIdentity,
                sessionId, spki(newP256KeyPair()));
        String eph = spki(newP256KeyPair());
        String transcript = SessionTranscript.initiatorForm(sessionId,
                UUID.fromString(conversation.get("id").asText()),
                UUID.fromString(userIdOf(alice)), UUID.fromString(userIdOf(bob)),
                SessionTranscript.SUITE, eph);
        String signature = sign(aliceIdentity.pair().getPrivate(), transcript);
        mockMvc.perform(post("/api/v1/conversations/" + conversation.get("id").asText() + "/sessions")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + sessionId + "\",\"suite\":\"" + SessionTranscript.SUITE
                                + "\",\"ephemeralPublic\":\"" + eph + "\",\"signature\":\"" + signature
                                + "\",\"identityKeyId\":\"" + aliceIdentity.keyId() + "\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("SESSION_ID_TAKEN"));
    }

    @Test
    @DisplayName("Messaging endpoints require authentication")
    void messagingEndpointsRequireAuth() throws Exception {
        mockMvc.perform(get("/api/v1/conversations"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }
}
