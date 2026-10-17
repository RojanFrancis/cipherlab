-- CipherLab v1.0 initial schema
-- Rules enforced here:
--   * UUID primary keys (assigned by the application, never by the client)
--   * identity metadata and ciphertext only — NO private keys, derived keys or plaintext
--   * uniqueness constraints that support replay detection (session + sender + sequence)

CREATE TABLE users (
    id            UUID         PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL
);

CREATE UNIQUE INDEX uq_users_username ON users (username);
CREATE UNIQUE INDEX uq_users_email ON users (email);

CREATE TABLE identity_keys (
    id          UUID        PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users (id),
    key_type    VARCHAR(32) NOT NULL,
    public_key  VARCHAR(512) NOT NULL,
    fingerprint VARCHAR(128) NOT NULL,
    key_version INT         NOT NULL,
    created_at  TIMESTAMP   NOT NULL,
    revoked_at  TIMESTAMP
);

CREATE UNIQUE INDEX uq_identity_keys_user_version ON identity_keys (user_id, key_version);

CREATE TABLE conversations (
    id         UUID      PRIMARY KEY,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE conversation_members (
    conversation_id UUID      NOT NULL REFERENCES conversations (id),
    user_id         UUID      NOT NULL REFERENCES users (id),
    joined_at       TIMESTAMP NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE crypto_sessions (
    id             UUID        PRIMARY KEY,
    conversation_id UUID       NOT NULL REFERENCES conversations (id),
    initiator_id    UUID       NOT NULL REFERENCES users (id),
    responder_id    UUID       NOT NULL REFERENCES users (id),
    suite           VARCHAR(64) NOT NULL,
    status          VARCHAR(32) NOT NULL,
    created_at      TIMESTAMP   NOT NULL,
    expires_at      TIMESTAMP
);

CREATE INDEX ix_crypto_sessions_conversation ON crypto_sessions (conversation_id);

CREATE TABLE messages (
    id              UUID        PRIMARY KEY,
    conversation_id UUID        NOT NULL REFERENCES conversations (id),
    session_id      UUID        NOT NULL REFERENCES crypto_sessions (id),
    sender_id       UUID        NOT NULL REFERENCES users (id),
    sequence_number BIGINT      NOT NULL,
    nonce           VARCHAR(64) NOT NULL,
    ciphertext      TEXT        NOT NULL,
    created_at      TIMESTAMP   NOT NULL
);

CREATE INDEX ix_messages_conversation_created ON messages (conversation_id, created_at);
-- Server-side replay/duplicate detection for an established session.
CREATE UNIQUE INDEX uq_messages_session_sender_seq ON messages (session_id, sender_id, sequence_number);

CREATE TABLE experiments (
    id             UUID        PRIMARY KEY,
    user_id        UUID        REFERENCES users (id),
    experiment_type VARCHAR(64) NOT NULL,
    result_summary VARCHAR(2000),
    created_at     TIMESTAMP   NOT NULL
);

CREATE INDEX ix_experiments_user ON experiments (user_id, created_at);

CREATE TABLE audit_events (
    id          UUID         PRIMARY KEY,
    actor_id    UUID         REFERENCES users (id),
    event_type  VARCHAR(64)  NOT NULL,
    resource_id VARCHAR(64),
    created_at  TIMESTAMP    NOT NULL
);

CREATE INDEX ix_audit_events_created ON audit_events (created_at);