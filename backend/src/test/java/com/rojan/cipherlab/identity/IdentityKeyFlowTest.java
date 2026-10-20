package com.rojan.cipherlab.identity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
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

import tools.jackson.databind.ObjectMapper;

/**
 * Identity key lifecycle: publish a real generated EC P-256 public key,
 * verify the server-computed fingerprint, list, revoke — and confirm the
 * client-holds-the-private-key invariant (the private half never travels).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class IdentityKeyFlowTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    private record User(String userId, String token) {
    }

    private User newUser() throws Exception {
        String username = "keyuser-" + UUID.randomUUID().toString().substring(0, 8);
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
        return new User(userId, token);
    }

    /** A real EC P-256 public key, DER-encoded and Base64'd — as a client would send. */
    private String generatedPublicKeyBase64() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        // Encoded point (uncompressed DER) is the standard upload form.
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    @Test
    @DisplayName("Publish a generated EC P-256 key, then see it in the caller's list with a fingerprint")
    void publishAndList() throws Exception {
        User user = newUser();
        String publicKey = generatedPublicKeyBase64();

        MvcResult publish = mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + publicKey + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyType").value("EC_P256"))
                .andExpect(jsonPath("$.keyVersion").value(1))
                .andExpect(jsonPath("$.fingerprint").isNotEmpty())
                .andExpect(jsonPath("$.revoked").value(false))
                .andReturn();
        String fingerprint = objectMapper.readTree(publish.getResponse().getContentAsString())
                .get("fingerprint").asText();

        // The fingerprint must be the SHA-256 (hex) of the submitted key bytes —
        // recomputed here independently to prove the server does not trust the client.
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        String expected = java.util.HexFormat.of()
                .formatHex(digest.digest(Base64.getDecoder().decode(publicKey)));
        org.junit.jupiter.api.Assertions.assertEquals(expected, fingerprint);

        mockMvc.perform(get("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].fingerprint").value(fingerprint));
    }

    @Test
    @DisplayName("Publishing a second key increments keyVersion — rotation keeps history")
    void rotationIncrementsVersion() throws Exception {
        User user = newUser();
        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyVersion").value(1));

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyVersion").value(2));

        mockMvc.perform(get("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].keyVersion").value(2)); // newest first
    }

    @Test
    @DisplayName("Revoke marks the key revoked; a second revoke is a 409")
    void revokeIsFinal() throws Exception {
        User user = newUser();
        MvcResult publish = mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String keyId = objectMapper.readTree(publish.getResponse().getContentAsString()).get("id").asText();

        mockMvc.perform(post("/api/v1/identity/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + user.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true))
                .andExpect(jsonPath("$.revokedAt").isNotEmpty());

        mockMvc.perform(post("/api/v1/identity/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + user.token()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("KEY_ALREADY_REVOKED"));
    }

    @Test
    @DisplayName("Revoked keys stay listed — history is never silently deleted")
    void revokedKeysRemainVisible() throws Exception {
        User user = newUser();
        MvcResult publish = mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String keyId = objectMapper.readTree(publish.getResponse().getContentAsString()).get("id").asText();
        mockMvc.perform(post("/api/v1/identity/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + user.token()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].revoked").value(true));
    }

    @Test
    @DisplayName("A user cannot revoke someone else's key (404, no existence oracle)")
    void cannotRevokeForeignKey() throws Exception {
        User alice = newUser();
        User mallory = newUser();
        MvcResult publish = mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        String keyId = objectMapper.readTree(publish.getResponse().getContentAsString()).get("id").asText();

        mockMvc.perform(post("/api/v1/identity/keys/" + keyId + "/revoke")
                        .header("Authorization", "Bearer " + mallory.token()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Peer lookup exposes any user's published keys — the fingerprint-verification path")
    void peerLookup() throws Exception {
        User alice = newUser();
        User bob = newUser();

        mockMvc.perform(get("/api/v1/identity/users/" + bob.userId() + "/keys")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + bob.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/v1/identity/users/" + bob.userId() + "/keys")
                        .header("Authorization", "Bearer " + alice.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].userId").value(bob.userId()));
    }

    @Test
    @DisplayName("Unknown key types and malformed Base64 are rejected with 400")
    void invalidKeysRejected() throws Exception {
        User user = newUser();

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"DES_56\",\"publicKey\":\"" + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\"!!!not-base64!!!\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_KEY"));
    }

    /** Any RSA keypair, DER + Base64, as a client would upload. */
    private String generatedRsaPublicKeyBase64(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
    }

    /** A real EC key on a NON-P-256 curve. */
    private String generatedP384PublicKeyBase64() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        return Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
    }

    @Test
    @DisplayName("Random bytes labeled EC_P256 are rejected — the key material is parsed, not trusted")
    void randomBytesRejected() throws Exception {
        User user = newUser();
        byte[] garbage = new byte[64];
        new java.security.SecureRandom().nextBytes(garbage);

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\""
                                + Base64.getEncoder().encodeToString(garbage) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_KEY"));
    }

    @Test
    @DisplayName("A P-384 key labeled EC_P256 is rejected — wrong curve")
    void wrongCurveRejected() throws Exception {
        User user = newUser();
        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\""
                                + generatedP384PublicKeyBase64() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_KEY"));
    }

    @Test
    @DisplayName("RSA modulus size is enforced: 1024-bit rejected, 2048-bit accepted")
    void rsaModulusSizeEnforced() throws Exception {
        User user = newUser();
        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"RSA_2048\",\"publicKey\":\""
                                + generatedRsaPublicKeyBase64(1024) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_KEY"));

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"RSA_2048\",\"publicKey\":\""
                                + generatedRsaPublicKeyBase64(2048) + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyType").value("RSA_2048"));
    }

    @Test
    @DisplayName("Declared type must match the actual key — RSA bytes cannot pose as EC_P256")
    void typeMismatchRejected() throws Exception {
        User user = newUser();
        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"EC_P256\",\"publicKey\":\""
                                + generatedRsaPublicKeyBase64(2048) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_KEY"));

        mockMvc.perform(post("/api/v1/identity/keys")
                        .header("Authorization", "Bearer " + user.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyType\":\"RSA_2048\",\"publicKey\":\""
                                + generatedPublicKeyBase64() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_KEY"));
    }

    @Test
    @DisplayName("Identity endpoints require authentication")
    void identityEndpointsRequireAuth() throws Exception {
        mockMvc.perform(get("/api/v1/identity/keys"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }
}
