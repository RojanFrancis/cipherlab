-- CipherLab v1.1 — authenticated session handshake.
--
-- Adds the public handshake material for the signed-ephemeral ECDH flow:
-- each side contributes an ephemeral P-256 public key and a signature over
-- a canonical transcript, made with that user's registered identity key.
-- Private halves NEVER reach this table (or any server-side store).
--
-- transcript_hash is the server's record of the exact transcript both
-- parties agreed on — auditable, but useless for decryption (it covers
-- public values only).

ALTER TABLE crypto_sessions ADD COLUMN initiator_ephemeral_public VARCHAR(256);
ALTER TABLE crypto_sessions ADD COLUMN initiator_signature         VARCHAR(256);
ALTER TABLE crypto_sessions ADD COLUMN initiator_identity_key_id   UUID;
ALTER TABLE crypto_sessions ADD COLUMN responder_ephemeral_public  VARCHAR(256);
ALTER TABLE crypto_sessions ADD COLUMN responder_signature         VARCHAR(256);
ALTER TABLE crypto_sessions ADD COLUMN responder_identity_key_id   UUID;
ALTER TABLE crypto_sessions ADD COLUMN transcript_hash             VARCHAR(64);

-- Sessions created before this migration never completed a cryptographic
-- handshake; an ACTIVE flag alone must not keep them usable. Expire them
-- (they can be superseded by new, fully-handshaken sessions).
UPDATE crypto_sessions SET status = 'EXPIRED' WHERE status = 'ACTIVE';
