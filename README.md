# CipherLab

**Interactive Cryptography Laboratory & Secure Communication Platform**

> Learn the mathematics. Test the protocol. Observe the security failure. Verify the protection.

A security-engineering portfolio project: an interactive cryptography lab (Diffie–Hellman
calculations, AES-256-GCM tampering experiments, HKDF derivation, HMAC/signature
demonstrations, a controlled MITM simulation) plus a deliberately scoped two-user encrypted
messaging prototype — built as a Java 21 / Spring Boot modular monolith with a
React + TypeScript frontend and PostgreSQL.

## Stack

| Layer        | Technology                                                   |
|--------------|--------------------------------------------------------------|
| Backend      | Java 21, Spring Boot 4, Maven                                |
| API          | REST (`/api/v1`), Bean Validation                            |
| Security     | Spring Security OAuth2 resource server (Nimbus HS256 + iss/exp), BCrypt |
| Persistence  | Spring Data JPA, PostgreSQL 17, Flyway                       |
| Frontend     | React 19, TypeScript, Vite                                   |
| Testing      | JUnit 5 (100 tests) + vitest (11), MockMvc over the real filter chain |
| Delivery     | Docker Compose, GitHub Actions CI                            |

## Repository layout

```
cipherlab/
├── backend/          # Spring Boot API (Maven wrapper committed)
│   └── src/main/java/com/rojan/cipherlab/
│       ├── crypto/       # AES-GCM, SHA-2/HMAC, HKDF, ECDSA, toy DH, MITM sim
│       ├── security/     # Nimbus JWT service + decoder policy, 401/403 bodies
│       ├── auth/         # register / login / me
│       ├── identity/     # public key registry + fingerprints
│       ├── messaging/    # conversations → sessions → ciphertext relay
│       ├── lab/          # the six educational endpoints
│       └── common/       # ApiError contract, audit trail, exceptions
├── frontend/         # React + TypeScript (Vite)
├── docs/             # architecture, threat model, API examples
├── docker-compose.yml
└── README.md
```

Toy/crypto-lab code and the real secure-channel code are kept in **separate packages**.
A value produced by the toy Diffie–Hellman demonstration must never be usable as a key
by the messaging implementation — the toy module is bounded to 512-bit inputs precisely
so it cannot be reused for real traffic.

## Quick start

Prerequisites: Java 21, Git, Docker + Docker Compose, Node.js + npm.

```bash
# 1. Start PostgreSQL
cp .env.example .env          # then edit DB_PASSWORD
docker compose up -d db
docker compose ps             # wait until healthy

# 2. Run the backend  (API on http://localhost:8080)
cd backend
./mvnw spring-boot:run

# 3. Run the frontend  (UI on http://localhost:5173, proxies /api to :8080)
cd ../frontend
npm ci
npm run dev

# 4. Verify
curl http://localhost:8080/actuator/health
# -> {"status":"UP"}
```

No Docker available (CI, restricted VM)? Use the H2-backed dev profile instead — it runs
Flyway against H2 in PostgreSQL compatibility mode, so no container is needed:

```bash
cd backend
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

Set `JWT_SECRET` (min 32 chars) in production; the app refuses to boot without a real one.

## Running the tests

```bash
cd backend && ./mvnw test      # 100 tests
cd frontend && npm test         # 11 vitest tests (Web Crypto E2EE layer)
cd frontend && npm run build   # tsc -b && vite build
```

Backend tests run on H2 (PostgreSQL mode) so they need no container. The MockMvc suites
exercise the **real security filter chain with real tokens issued by the running service**,
not test doubles.

## What is implemented (v1.0)

**Crypto lab** — six experiments, each making an invisible property visible:

| Experiment | The point |
|---|---|
| AES-256-GCM tamper | Flip one bit of ciphertext, tag, key or nonce → `400 INVALID_CIPHERTEXT`, no plaintext |
| Hash & HMAC | A hash anyone can recompute vs a MAC only the key-holder can |
| Diffie–Hellman | Two strangers arrive at a shared secret over a public channel |
| HKDF | One secret → many keys; the `info` label binds each to its purpose |
| Signatures | Verify the original, watch the tampered copy fail |
| MITM | The same attack succeeds unauthenticated and dies with signatures |

**Secure messaging** — register/login (BCrypt), identity keys with
server-computed fingerprints and **parsed key-material validation**, conversations,
and a two-party session handshake: each side contributes a browser-generated
ephemeral P-256 key signed with its identity key over a canonical transcript
(verified by the peer *and* the server before `ACTIVE`), then derives
directional AES-256-GCM keys locally with HKDF-SHA-256. The relay stores
only ciphertext, nonces and replay-tracking metadata. Messages carry a
fresh 96-bit nonce and bind `sessionId|conversationId|senderId|sequence`
as additional authenticated data; tampered, relocated or replayed
envelopes are rejected.

**Security behaviour**, each pinned by a test:

- Replay of a captured envelope → `400 REPLAYED_MESSAGE`, detected by the
  `(session, sender, sequence)` unique index **without decrypting anything**.
- A substituted ephemeral key, a signature from the wrong identity key, or
  a revoked/foreign identity key → `400 HANDSHAKE_SIGNATURE_INVALID` /
  `INVALID_IDENTITY_KEY` — verified server-side, and the peer client
  re-verifies the initiator's signature before contributing its own key.
- An encrypted envelope moved to another sequence, sender, conversation or
  session fails the recipient's GCM authentication (AAD binding).
- Non-members get `404`, never `403` — membership is not probe-able.
- Wrong password and unknown username return the **identical** `401` body — no username oracle.
- Tokens are verified by the standard Nimbus stack: signature, **issuer**
  and expiry; `alg=none` and swapped algorithms are rejected by the library.
- The app **refuses to boot** without an explicit `JWT_SECRET`, with a
  secret under 32 chars, or with the publicly known dev secret outside the
  `dev` profile.
- Password hashes never appear in any response; audit rows carry no secrets.
- Every error, including 401/403 from the filter chain, uses one `{code, message, traceId}` shape.

See [docs/threat-model.md](docs/threat-model.md) for the adversaries this defends against
and the trade-offs that were deliberate.

## Documentation

- [docs/architecture.md](docs/architecture.md) — layering, security zones, the token pipeline, replay design, why audit writes have two timings
- [docs/threat-model.md](docs/threat-model.md) — assets, six adversary classes, trust boundaries, non-goals
- [docs/api-examples.md](docs/api-examples.md) — runnable `curl` for every endpoint, pasted verbatim from a live server

## Continuous integration

`.github/workflows/ci.yml` runs two jobs on every push and pull request: the Maven test
suite on Java 21 (Temurin, with dependency caching), and `npm ci` → `oxlint` → `tsc -b` →
`vite build` on Node 22, uploading the production bundle as an artifact.

## Security notes (v1.0 scope)

- The database stores **identity metadata and ciphertext only** — never private keys,
  derived session keys or message plaintext. There is no column anywhere that can
  decrypt user traffic.
- Passwords are hashed with BCrypt (adaptive), never plain SHA-256.
- `/api/v1/lab/**` endpoints are **educational demonstrations**; they are never used
  by the secure messaging path.
- The two-user messaging prototype is a documented prototype with a threat model,
  not a claim of production-grade end-to-end encryption.

### Known limits (v1.0)

Stated plainly rather than papered over — each is listed as a non-goal in the threat model:

- **No forward secrecy.** Sessions use one key for their lifetime; a ratchet is the v2 fix.
- **No TLS, rate limiting, or account lockout.** Required in any real deployment.
- **Two-party sessions only.** The replay constraint is correct for two senders, not groups.
- **Tokens in `localStorage`.** Chosen so the JWT is inspectable in DevTools for teaching.
- **Identity private keys live in browser memory only**, with a user-held
  backup file for restore — never localStorage, never the server. A lost
  backup means a new identity fingerprint your contact must re-verify.
- **Fingerprint verification is trust-on-first-use** unless users compare
  out of band as the UI instructs; nothing technically forces the comparison.
- **Client-side encryption keys are never rotated mid-session** (no ratchet);
  a ratchet is the natural v2.
