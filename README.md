# CipherLab

**Interactive Cryptography Laboratory & Secure Messaging Prototype**

> Learn the mathematics. Test the protocol. Observe the security failure. Verify the protection.

CipherLab is a security-engineering portfolio project that makes cryptographic concepts tangible through interactive experiments and a two-user encrypted messaging prototype.

It combines a **Java 21 / Spring Boot backend** with a **React + TypeScript frontend**, demonstrating cryptographic primitives, authentication, encrypted message handling, replay rejection, and signed handshake verification.

**Project status:** v1.1.1 — tested development build  
**Scope:** Educational cryptography laboratory and security-focused messaging prototype. Not intended for production use.

## Highlights

- **Interactive cryptography lab:** AES-256-GCM, hashing, HMAC, Diffie–Hellman, HKDF, digital signatures, and a controlled man-in-the-middle simulation.
- **Browser-side cryptography:** Web Crypto APIs for key generation, signatures, key derivation, and authenticated encryption.
- **Two-user encrypted messaging:** Directional session keys, AES-GCM message encryption, and authenticated message context.
- **Handshake authentication:** Signature and transcript verification before session keys are derived.
- **Replay rejection:** Detects previously relayed message envelopes using session, sender, and sequence metadata.
- **Backend security:** Spring Security, JWT validation, BCrypt password hashing, request validation, and consistent API errors.
- **Automated verification:** 100 backend tests and 20 frontend tests passed in the tested revision.

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Java 21, Spring Boot 4, Maven |
| API | REST, Bean Validation |
| Authentication | Spring Security OAuth2 Resource Server, Nimbus JWT, BCrypt |
| Persistence | Spring Data JPA, PostgreSQL 17, Flyway |
| Frontend | React 19, TypeScript, Vite |
| Cryptography | Java Cryptography Architecture (JCA/JCE), browser Web Crypto API |
| Testing | JUnit 5, MockMvc, Vitest |
| Development | Docker Compose, H2 development profile |
| CI | GitHub Actions |

## Architecture

CipherLab separates educational cryptography demonstrations from the messaging implementation.

```text
React + TypeScript frontend
          |
          | REST API
          v
Spring Boot backend
  ├── Authentication and authorization
  ├── Identity and public-key registry
  ├── Conversation and session management
  ├── Encrypted message relay
  ├── Cryptography lab endpoints
  └── Persistence and audit handling
          |
          v
PostgreSQL / H2 development profile

Browser Web Crypto
  ├── Identity and ephemeral key operations
  ├── Handshake signature verification
  ├── ECDH key agreement
  ├── HKDF key derivation
  └── AES-GCM message encryption/decryption
```

The cryptography lab is designed for learning and experimentation. Its toy Diffie–Hellman demonstration is not used to establish messaging session keys.

## Cryptography lab

The laboratory includes six experiments:

| Experiment | What it demonstrates |
|---|---|
| AES-256-GCM tampering | Authentication failure when ciphertext, tag, nonce, or other inputs are modified |
| Hashing and HMAC | The difference between an unkeyed digest and a keyed message authentication code |
| Diffie–Hellman | How two parties can derive a shared secret over a public channel |
| HKDF | Deriving purpose-specific keys from shared secret material |
| Digital signatures | Authenticating signed data and detecting modifications |
| Man-in-the-middle simulation | Comparing an unauthenticated exchange with a signature-protected exchange |

The experiments are educational demonstrations, not substitutes for a vetted production cryptographic protocol.

## Encrypted messaging

The messaging prototype supports registration and login, identity-key publication, conversations, session handshakes, and encrypted message exchange.

### Session establishment

1. Participants publish identity public keys.
2. The initiator creates an ephemeral P-256 key and signs the handshake transcript.
3. The responder validates the expected session context and the initiator's signed handshake.
4. The responder contributes its ephemeral key and signs the canonical handshake transcript.
5. The initiator verifies the responder's identity-key reference, fingerprint, signature, ephemeral key, and session context before deriving session keys.
6. Both clients derive directional AES-256-GCM keys using ECDH and HKDF-SHA-256.

### Message protection

- Plaintext encryption and decryption occur in the browser.
- Messages use AES-256-GCM authenticated encryption with a fresh 96-bit nonce.
- Additional authenticated data binds the session, conversation, sender, and sequence number.
- The server relays encrypted envelopes and maintains replay-tracking metadata.
- Tampered envelopes fail authentication; previously relayed messages are rejected.

These protections are part of a deliberately scoped prototype. They do not establish that the application is suitable for sensitive real-world communications.

## Security engineering

The project includes defensive behaviors that are exercised by automated tests:

- Rejects invalid ciphertext and authentication tags.
- Verifies handshake signatures and transcript context.
- Rejects substituted or invalid responder ephemeral keys.
- Checks identity-key ownership, fingerprint consistency, and revocation state.
- Rejects replayed message envelopes.
- Validates JWT signatures, issuer, and expiration using the standard Nimbus stack.
- Uses BCrypt for password hashing.
- Avoids exposing password hashes in API responses.
- Returns consistent structured API errors.
- Rejects invalid or missing production JWT secret configuration.

See the [threat model](docs/threat-model.md) for the trust boundaries, assumptions, adversaries, and non-goals.

## My engineering focus

This project brings together backend engineering and applied security concepts.

Areas of focus include:

- Java and Spring Boot REST API development.
- Authentication, authorization, validation, and persistence.
- Frontend integration with React and TypeScript.
- Cryptographic key handling and authenticated encryption flows.
- Signed handshake verification and replay protection.
- Automated tests for valid flows, tampering, and invalid handshake scenarios.
- Manual testing of the application and encrypted messaging between two users.

AI-assisted development tools were used during implementation. The project was also evaluated through code review, automated tests, and manual application testing. The implementation and test results should be assessed on their merits rather than assuming every line was written manually.

## Repository layout

```text
cipherlab/
├── backend/
│   └── src/main/java/com/rojan/cipherlab/
│       ├── crypto/
│       ├── security/
│       ├── auth/
│       ├── identity/
│       ├── messaging/
│       ├── lab/
│       └── common/
├── frontend/
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   └── api-examples.md
├── .github/workflows/
├── docker-compose.yml
├── .env.example
├── PROJECT_BRIEF.md
└── README.md
```

## Quick start

### Prerequisites

- Java 21
- Node.js 22 and npm
- Git
- Docker Compose for the PostgreSQL setup

### 1. Clone the repository

```bash
git clone https://github.com/RojanFrancis/cipherlab.git
cd cipherlab
```

### 2. Start the database

```bash
cp .env.example .env
```

Edit `.env` and set a local development database password, then run:

```bash
docker compose up -d db
docker compose ps
```

Wait until the database is healthy before starting the backend.

### 3. Start the backend

In a terminal at the repository root:

```bash
cd backend
./mvnw spring-boot:run
```

The API is available at `http://localhost:8080`.

### 4. Start the frontend

In another terminal at the repository root:

```bash
cd frontend
npm ci
npm run dev
```

The development UI is available at `http://localhost:5173`.

### 5. Check backend health

```bash
curl http://localhost:8080/actuator/health
```

The expected response reports a healthy application.

### Running without Docker

The H2-backed development profile can be used when Docker is unavailable:

```bash
cd backend
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

Use the development profile only for local development, not production deployment.

## Running the tests

Run these commands from the repository root:

```bash
(cd backend && ./mvnw test)
(cd frontend && npm ci && npm test)
(cd frontend && npm run build)
```

Results from the tested v1.1.1 revision:

| Check | Result |
|---|---:|
| Backend tests | 100 passed |
| Frontend tests | 20 passed |
| TypeScript compilation and Vite production build | Passed |
| npm dependency audit | 0 vulnerabilities reported |

The frontend tests cover identity-key handling, transcript signatures, directional session keys, authenticated encryption, and initiator-side responder authentication.

The backend tests run against H2 in PostgreSQL compatibility mode, so the test suite does not require a running PostgreSQL container.

## Documentation

- [Architecture](docs/architecture.md) — application layers, security boundaries, authentication, and replay handling.
- [Threat model](docs/threat-model.md) — assets, adversaries, trust assumptions, and non-goals.
- [API examples](docs/api-examples.md) — API request and response examples.

## Security limitations

CipherLab is a learning and portfolio project, **not a production-ready secure messaging application**.

Known limitations include:

- **No forward secrecy through a ratchet:** session keys are not continuously rotated using a messaging ratchet.
- **No production deployment hardening:** TLS termination, rate limiting, account lockout, monitoring, and operational controls must be addressed before real deployment.
- **Trust-on-first-use:** identity fingerprints may need out-of-band verification to protect against first-contact identity substitution.
- **Browser-based key risks:** private identity keys and session material remain subject to browser and endpoint compromise.
- **Local storage token exposure:** the prototype stores its authentication token in browser local storage.
- **Two-party scope:** replay handling is designed for two-party sessions, not group messaging.
- **No independent security certification:** passing automated tests does not prove the absence of vulnerabilities.

For production use, the cryptographic protocol and implementation would require independent security review, a vetted messaging protocol, stronger key lifecycle management, deployment hardening, and additional adversarial testing.

## Future improvements

Potential next steps include:

- Forward secrecy and a reviewed ratcheting protocol.
- Stronger identity verification and key-change warnings.
- Rate limiting, account lockout, and operational monitoring.
- Browser end-to-end integration tests and expanded adversarial test coverage.
- Reproducible deployment and security review documentation.

---

**CipherLab** — an exploration of applied cryptography, backend engineering, and secure communication design.

[View the source on GitHub](https://github.com/RojanFrancis/cipherlab)