# CipherLab — Complete Project Brief (AI Handoff Document)

> This document is self-contained. An agent with no prior context should be able to
> understand the project, run it, verify it, and continue working on it using only
> this file plus the repository. Written 2026-10-20, reflecting the state at commit
> `9abd3f4` + this brief.

---

## 1. What this project is

**CipherLab** — an interactive cryptography laboratory **and** a deliberately scoped
two-user secure-messaging prototype, built as a portfolio/security-engineering project.

Two halves:

1. **Crypto Lab** — six educational endpoints + UI screens that make cryptographic
   properties visible: AES-256-GCM tamper detection, hash vs HMAC, toy Diffie–Hellman,
   HKDF key derivation, ECDSA signatures, and a controlled MITM simulation that succeeds
   without signatures and fails with them.
2. **Secure Messenger** — register/login (BCrypt + hand-rolled HS256 JWT), public-key
   identity registry with server-computed fingerprints, conversations, a two-party
   session lifecycle (`PENDING` → `ACTIVE`), and a **ciphertext-only relay** with
   server-side replay rejection.

Central invariant: **the server never holds a key that can decrypt user traffic.**
No column in the database stores private keys, derived session keys, or plaintext.

The lab code and the real messaging code live in **separate packages**. The toy DH
module is deliberately bounded to 512-bit inputs so its outputs *cannot* be reused as
real keys.

---

## 2. Current status

**Complete for v1 scope. Working tree clean. All checks green.**

- 87/87 backend tests pass (`./mvnw -B clean test`, exit 0)
- Frontend: `oxlint` 0 warnings / 0 errors; `tsc -b && vite build` exit 0
- Live end-to-end verified: register → 201, login → 200 (JWT issued), `/auth/me` with
  that token → 200; `/lab/hash` returns the correct NIST SHA-256 vector for "abc";
  signed-out protected call → the standard 401 error body
- Not yet done (external): pushing to GitHub so the CI workflow actually executes;
  any production deployment.

### Git history (chronological)

```
c4deca5 Initial cloud project
c53c1a7 Import cloud project files
808debc chore: initialize CipherLab project (Day 1)
81fc0cd chore: add docs/ placeholder for architecture and threat-model docs (Week 4)
26d0a3d feat(lab): AES-256-GCM, SHA-2/HMAC, and toy Diffie–Hellman services with tests
df0f73d feat(lab): HKDF-SHA-256, ECDSA P-256 signatures, and MITM simulation
980697b feat(auth,messaging): JWT auth, identity keys, and ciphertext relay
3ab9043 feat(frontend): crypto lab and secure messenger UI
26cce0c refactor(frontend): split auth hook for Fast Refresh and fix lint warnings
9abd3f4 docs: add architecture, threat model, API examples, and CI pipeline
```

---

## 3. Stack

| Layer | Technology |
|---|---|
| Backend | Java 21, Spring Boot 4, Maven (wrapper committed: `backend/mvnw`) |
| API | REST under `/api/v1`, Bean Validation on every request DTO |
| Security | Spring Security filter chain, hand-rolled HS256 JWT (no JWT library), BCrypt |
| Persistence | Spring Data JPA, Flyway, PostgreSQL 17 (prod) / H2 in PostgreSQL mode (dev/tests) |
| Frontend | React 19, TypeScript, Vite, oxlint |
| Tests | JUnit 5 + MockMvc **over the real security filter chain with real tokens** |
| Delivery | Docker Compose (Postgres), GitHub Actions CI |

---

## 4. How to run it

```bash
# --- with Docker (full stack) ---
cp .env.example .env            # edit DB_PASSWORD
docker compose up -d db         # wait until healthy
cd backend && ./mvnw spring-boot:run                 # API on :8080
cd ../frontend && npm ci && npm run dev              # UI on :5173, proxies /api → :8080

# --- without Docker (H2 dev profile) ---
cd backend && ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev

# --- tests / build (exactly what CI runs) ---
cd backend && ./mvnw -B clean test                   # 87 tests, no container needed
cd frontend && npm ci && npm run lint && npm run build   # oxlint, then tsc -b + vite build
```

- Production profile requires `JWT_SECRET` (min 32 chars); the app refuses to boot
  without a real one. Dev/test profiles generate one.
- Health check: `curl http://localhost:8080/actuator/health` → `{"status":"UP"}`.

---

## 5. Repository map

```
cipherlab/
├── README.md                        # user-facing overview, quick start, v1 scope
├── PROJECT_BRIEF.md                 # this document
├── docker-compose.yml               # Postgres 17 + backend (spec-exact, pre-existing)
├── .env.example                     # DB_PASSWORD etc.
├── .github/workflows/ci.yml         # two jobs: Maven/Java21 + Node22 lint/build
├── docs/
│   ├── architecture.md              # layering, security zones, token pipeline, audit timings
│   ├── threat-model.md              # assets, six adversary classes, non-goals
│   └── api-examples.md              # runnable curl for every endpoint
├── backend/
│   ├── pom.xml, mvnw, mvnw.cmd      # Maven wrapper committed; Spring Boot 4, Java 21
│   └── src/
│       ├── main/java/com/rojan/cipherlab/
│       │   ├── CipherLabApplication.java
│       │   ├── config/SecurityConfig.java        # the three security zones
│       │   ├── security/                         # JwtService, JwtAuthenticationFilter,
│       │   │                                     # AuthenticatedUser, SecurityErrorResponses
│       │   ├── common/                           # ApiError, ApiExceptionHandler, 6 exception
│       │   │                                     # types, AuditService/AuditEvent, Experiment
│       │   ├── auth/                             # AuthController/Service, User, UserRepository
│       │   ├── identity/                         # public key registry + fingerprints
│       │   ├── messaging/                        # conversations, sessions, relay
│       │   ├── lab/                              # LabController/Service + request/response DTOs
│       │   └── crypto/                           # primitives, no Spring, no DB access
│       │       ├── aes/AesGcmService.java
│       │       ├── hashing/HashingService.java
│       │       ├── kdf/HkdfService.java
│       │       ├── keyexchange/ToyDiffieHellmanService.java
│       │       ├── signatures/SignatureService.java
│       │       └── mitm/MitmSimulation.java
│       ├── main/resources/
│       │   ├── application.yml                   # default: PostgreSQL
│       │   ├── application-dev.yml               # H2 PostgreSQL-compat mode
│       │   └── db/migration/V1__initial_schema.sql
│       └── test/java/...                         # 13 test classes, 87 tests (see §9)
└── frontend/
    ├── vite.config.ts                            # dev proxy /api → localhost:8080
    ├── index.html, tsconfig*.json, .oxlintrc.json
    └── src/
        ├── main.tsx, App.tsx (2-tab shell), App.css, index.css
        ├── lib/api.ts        # typed fetch client for EVERY endpoint + ApiError class
        ├── lib/auth.tsx      # AuthProvider: token in localStorage ('cipherlab.token')
        ├── lib/useAuth.ts    # context + hook (separate file for Fast Refresh)
        ├── lib/b64.ts        # base64/hex helpers
        ├── lab/Lab.tsx       # six experiment screens
        └── messaging/Messenger.tsx  # login gate, conversations, session, relay, replay demo
```

---

## 6. Backend architecture

Requests flow **controller → service → repository**. Crypto primitives are plain
classes (no Spring, no DB) so they unit-test in isolation. Dependency direction is
strictly downward: `AesGcmService` does not know what HTTP is; `MessagingService`
does not implement AES.

### Security zones (`SecurityConfig`)

1. `/actuator/health` — liveness only.
2. **Public:** `/api/v1/lab/**` (stateless demos, no user data), `POST /api/v1/auth/register`,
   `POST /api/v1/auth/login` (the only ways to get a token).
3. **Authenticated:** everything else — the JWT filter verifies the bearer token per
   request; there is no HTTP session anywhere.

CSRF is disabled **by construction**: no cookies exist, the token travels in the
`Authorization` header, which cross-site forms/images cannot set.

### JWT pipeline (`JwtService`) — hand-rolled, no library

- `alg` header must be exactly `HS256`; `none`/swapped algorithms rejected before any
  crypto runs (classic `alg=none` defense).
- Constant-time MAC comparison via `MessageDigest.isEqual` (not `String.equals`).
- Verification order: **format → algorithm → signature → claims.** Expiry is checked
  only after the signature passes, so a forged `exp` cannot survive a bad signature.

### Error contract

Every error — from any layer **including the security filter chain** — has one shape:

```json
{ "code": "INVALID_CIPHERTEXT", "message": "...", "traceId": "..." }
```

No stack traces, no secrets, no plaintext ever leave the process.
- Wrong password and unknown username return the **identical** `401 INVALID_CREDENTIALS`
  (no username oracle).
- Non-members get `404`, never `403` (membership is not probe-able).

### Audit trail (`AuditService`) — two write timings, both load-bearing

- `record(...)` for events alongside a **successful** change: defers the write until
  after commit (FK integrity — a `REQUIRES_NEW` write during registration referenced an
  uncommitted `users` row and violated the FK; a write inside the caller's transaction
  gets erased by rollback).
- `recordSecurityEvent(...)` for events **caused by a rejection**: writes immediately
  in its own transaction so evidence survives the rollback that the thrown rejection
  causes (e.g. replay rejections).
- Audit failures are logged and swallowed — losing a row must not turn a successful
  login into a 500.

---

## 7. Database schema (Flyway `V1__initial_schema.sql`)

UUID PKs assigned by the application, never accepted from a client.

| Table | Purpose / notable columns |
|---|---|
| `users` | `username`/`email` unique; `password_hash` (BCrypt — never returned by any endpoint) |
| `identity_keys` | **public_key only**, fingerprint, `key_version`; unique `(user_id, key_version)`; `revoked_at` |
| `conversations` | id + created_at only |
| `conversation_members` | composite PK `(conversation_id, user_id)` — membership checks ride this |
| `crypto_sessions` | initiator/responder, suite, status (`PENDING`/`ACTIVE`), `expires_at`. **No key material.** |
| `messages` | ciphertext + nonce + `sequence_number`; **`uq_messages_session_sender_seq` unique on `(session_id, sender_id, sequence_number)` = replay detection** |
| `experiments` | optional lab-run log (user_id nullable) |
| `audit_events` | actor, event_type, resource_id — no secrets |

`ddl-auto: validate` — Hibernate refuses to boot against a schema it doesn't recognize,
so a migration/entity mismatch fails loudly at boot. Entities use `LocalDateTime` (UTC)
because the schema declares `TIMESTAMP`, not `TIMESTAMP WITH TIME ZONE`.

**Replay design:** the service pre-checks for a clean `400 REPLAYED_MESSAGE`, and still
catches `DataIntegrityViolationException` for concurrent double-submits. *The unique
index is the source of truth; the check is courtesy.* The constraint is per-sender:
two parties may legitimately use the same sequence number.

---

## 8. API reference (24 endpoints)

All bodies/errors follow §6's contract. **[A]** = requires `Authorization: Bearer <jwt>`.

### Lab — all public, all POST, `/api/v1/lab` (educational only; never called by the messenger)

| Path | Request → Response |
|---|---|
| `/aes/encrypt` | `{plaintext, aad?}` → `{algorithm, key, nonce, ciphertext, tag, combined, securityNote}` (separated ct/tag so the UI can tamper with each) |
| `/aes/decrypt` | `{key, nonce, ciphertext, tag, aad?}` (all Base64; 32/12/16-byte lengths checked) → `{algorithm, plaintext, authenticated, note}`; tamper → `400 INVALID_CIPHERTEXT` |
| `/hash` | `{input, algorithm}` → `{algorithm, digest}` |
| `/hmac` | `{input, key}` → `{algorithm, mac, note}` |
| `/diffie-hellman` | `{p, g, alicePrivate, bobPrivate}` decimal strings ≤160 digits → `{p,g,alicePrivate,bobPrivate,alicePublic,bobPublic,sharedSecret,steps[],securityNote}` |
| `/hkdf` | `{ikm, salt?, info?, outputLength 1..8160}` (Base64 ikm/salt) → `{prkHex, outputHex, steps[], securityNote}` |
| `/signatures/keygen` | (no body) → `{algorithm, privateKey, publicKey, fingerprint, securityNote}` (ECDSA P-256) |
| `/signatures/sign` | `{message, privateKey}` → `{algorithm, signature, messageSha256}` |
| `/signatures/verify` | `{message, signature, publicKey}` → `{valid, fingerprint, explanation}` |
| `/mitm/simulate` | `{mode: "unauthenticated"|"authenticated"}` → `{mode, participants[], sharedSecrets{map}, malloryCanRead, substitutionDetected, steps[], securityNote}` |

### Auth — `/api/v1/auth`

| Route | Auth | Notes |
|---|---|---|
| `POST /register` | public | `{username, email, password}` → `201` user body. BCrypt. Duplicate → conflict. |
| `POST /login` | public | `{username, password}` → `{accessToken, user, ...}` (JWT). Identical 401 for wrong password vs unknown user. |
| `GET /me` | **[A]** | current user profile |

### Identity — `/api/v1/identity` — all **[A]**

| Route | Notes |
|---|---|
| `POST /keys` | publish public key; server **recomputes the fingerprint** independently and stores that (never trusts the client's) |
| `GET /keys` | my keys |
| `POST /keys/{keyId}/revoke` | revoke is final |
| `GET /users/{userId}/keys` | another user's public keys |

### Messaging — `/api/v1` — all **[A]**

| Route | Notes |
|---|---|
| `POST /conversations` | `{partnerId}`; non-members/partners → 404 semantics |
| `GET /conversations` | mine (membership-based) |
| `GET /conversations/{id}/messages` | members only |
| `POST /conversations/{id}/sessions` | creates session `PENDING`, responder must activate |
| `GET /sessions/{sessionId}` | status polling |
| `POST /sessions/{sessionId}/activate` | `PENDING → ACTIVE`; relay rejects otherwise |
| `POST /sessions/{sessionId}/messages` | the relay: `{sequenceNumber, nonce, ciphertext}` → `201`, or `400 REPLAYED_MESSAGE` |

---

## 9. Testing (87 tests, 13 classes)

Run: `cd backend && ./mvnw -B clean test` (H2 PostgreSQL mode — no container).

| Suite | Proves |
|---|---|
| `AesGcmServiceTest` | roundtrip incl. unicode/empty; tamper across ct/tag/nonce/key/AAD; nonce freshness |
| `HashingServiceTest` | NIST SHA-2 vectors, RFC 4231 HMAC vectors |
| `HkdfServiceTest` | RFC 5869 vectors |
| `SignatureServiceTest` | sign/verify, tamper rejection, invalid-key fail-closed |
| `ToyDiffieHellmanServiceTest` | textbook `p=23 → s=2`, bounds enforcement |
| `MitmSimulationTest` | attack succeeds unauthenticated; substitution caught with signatures |
| `JwtServiceTest` | roundtrip, tampered payload/signature, `alg=none`, wrong secret, expiry |
| `AuthFlowTest` | register→login→/me over the **real filter chain**; duplicate identity; oracle-free errors; hash never leaks |
| `IdentityKeyFlowTest` | publish with independently recomputed fingerprint; rotation; revoke final |
| `MessagingFlowTest` | full flow; replay rejected; lifecycle enforced; outsiders get 404 |
| `LabControllerTest` | all lab endpoints incl. validation bounds |
| `AuditTrailTest` | auth + replay events recorded and carry no secrets |
| `CipherLabApplicationTests` | context boots |

MockMvc tests use **real tokens issued by the running service**, not test doubles —
the whole JWT pipeline is exercised end to end.

Frontend has no unit tests (lint + tsc + build only) — known gap, see §12.

---

## 10. Frontend

- **`lib/api.ts`** — one typed `fetch` wrapper for every endpoint; throws `ApiError`
  carrying `{code, message, traceId}`; token injected via `setTokenProvider` callback.
- **`lib/auth.tsx` + `lib/useAuth.ts`** — `AuthProvider` stores the JWT in
  `localStorage['cipherlab.token']` (deliberate: the JWT is inspectable in DevTools for
  teaching; a real deployment should weigh httpOnly cookies). On load it calls `/auth/me`;
  invalid token fails quietly to logged-out. `useAuth` lives in a **separate file** so
  `auth.tsx` exports only a component — required for Fast Refresh (bundler disables hot
  reload for files mixing components and hooks).
- **`lab/Lab.tsx`** — six experiments; the AES screen lets you flip bits in ciphertext,
  tag, key or nonce independently and shows the 400.
- **`messaging/Messenger.tsx`** — login gate → conversation list → session lifecycle →
  relay. Includes a **"Send replayed envelope"** button that resubmits the last sequence
  so the user watches the server reject it.

**Honest limitation (documented in README + threat model):** the messenger UI currently
sends **Base64 of the plaintext** as the "ciphertext" envelope so the UI can show a real
value while demonstrating the *server-side* contract (session lifecycle + replay
rejection). The server still never sees a key, and the relay path is real. Replacing
this with actual browser-side ECDH + HKDF + AES-GCM via Web Crypto is the designated
v2 milestone (§12).

---

## 11. CI (`.github/workflows/ci.yml`)

Two jobs on push to `main` and on PRs (with concurrency cancellation):

- **backend:** setup-java Temurin 21 (Maven cache) → `./mvnw -B clean test` →
  `./mvnw -B -DskipTests package`
- **frontend:** setup-node 22 (npm cache on `frontend/package-lock.json`) →
  `npm ci` → `npm run lint` → `npm run build` (`tsc -b` fails first on type errors) →
  upload `frontend/dist` artifact (7 days)

Every command in CI has been verified locally and passes. **The workflow itself has
never executed because the branch has not been pushed to GitHub.**

---

## 12. Threat model summary & known limits

Full version: `docs/threat-model.md`. Non-goals stated plainly:

- **No forward secrecy** — one key per session lifetime; a ratchet is the v2 fix.
- **No TLS, rate limiting, or account lockout.**
- **Two-party sessions only** — the per-sender replay constraint is correct for two
  senders, not groups.
- **Tokens in localStorage** (teaching choice).
- **Base64 envelope in the UI, not Web Crypto** (see §10).
- Toy DH bounded to 512 bits **so it cannot be reused for real traffic**.

Adversary classes covered: passive network observer, active MITM, authenticated-user
malicious to peers, relay-as-adversary (it can't read), replay attacker, username oracle
prober.

---

## 13. Verification log (what was proven, and how)

| Check | Command / method | Result |
|---|---|---|
| Backend suite | `./mvnw -B clean test` (exit status captured) | **87/87, exit 0** |
| Lint | `npm run lint` (oxlint) | **0 warnings, 0 errors, exit 0** |
| Types + bundle | `npm run build` (`tsc -b` then vite) | **exit 0**, ~247 kB JS |
| Install reproducibility | `npm ci` from lockfile | exit 0, 0 vulnerabilities |
| Live auth flow | register → login → `/auth/me` via dev proxy | 201 → 200 (JWT) → 200 |
| Lab correctness | `POST /lab/hash {"input":"abc"}` | digest `ba7816bf…15ad` = correct NIST vector |
| Error contract | signed-out `GET /auth/me` | 401 `{code: UNAUTHENTICATED, message, traceId}` |
| Archive | `unzip -t cipherlab-v1.zip` | exit 0, no errors, 158 files |

Environment caveats seen during development (VM-only, not code issues): preview
hostnames change on workspace restore (restart Vite with the new
`__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS`), and `node_modules`/jar do not survive
restore (`npm ci` / `./mvnw -DskipTests package` to rebuild).

---

## 14. Natural next steps (v2 candidates, in priority order)

1. **Web Crypto in the browser** — real ECDH (P-256) → HKDF → AES-256-GCM in
   `Messenger.tsx`, so the relay carries true end-to-end ciphertext. Server changes
   needed: publish raw public keys (already stored), possibly key-confirmation messages.
2. **Session ratchet** — rotate keys per message epoch for forward secrecy.
3. **Push to GitHub** — makes the CI workflow actually run.
4. **Messaging frontend tests** (currently lint/build only) and rate limiting.

---

## 15. Rules for a follow-up agent

- **Never** let toy `crypto/` code feed the messaging path; keep the 512-bit bound.
- Keep the single error shape `{code, message, traceId}` everywhere, including new
  filter-chain paths.
- Preserve the two audit-write timings (§6) — both were real bugs, covered by
  `AuditTrailTest`.
- Schema changes go through Flyway + `ddl-auto: validate`; never widen the schema to
  store key material (violates the central invariant).
- Tests run on H2 — keep them container-free; CI depends on that.
- Match existing style: records for DTOs, constructor injection, services own
  authorization, controllers own only HTTP binding.
