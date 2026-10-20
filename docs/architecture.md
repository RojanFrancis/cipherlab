# CipherLab Architecture

A teaching-oriented encrypted-messaging backend with a browser lab. The
project exists to make cryptographic properties *visible*: every design
choice below is paired with the failure it prevents and the demonstration
that shows it.

```
frontend (React 19 + Vite)
   │  same-origin /api  (Vite proxy in dev)
   ▼
Spring Boot 4.1  (Java 21, stateless, JWT per request)
   ├── security      JWT (Nimbus resource server: HS256 + iss + exp), 401/403 bodies
   ├── lab           six educational endpoints — no auth, no user data
   ├── auth          register / login (BCrypt), /me
   ├── identity      public key registry + fingerprints (keys are parsed and validated)
   ├── messaging     conversations → signed handshake → ciphertext relay
   ├── crypto        AES-GCM, SHA-2/HMAC, HKDF, ECDSA, toy DH, MITM sim
   └── common        ApiError contract, audit trail, exceptions
   ▼
PostgreSQL 17 (Flyway migrations)   ·  H2 in PostgreSQL mode for dev/tests
```

## Layering

Requests flow **controller → service → repository**, with the crypto
primitives kept as small, dependency-light classes so they can be unit
tested without Spring:

| Layer | Responsibility | Must never do |
|---|---|---|
| Controller | HTTP binding, Bean Validation, status codes | Hold business rules |
| Service | Authorization, invariants, transactions, audit | Parse HTTP |
| Repository | Persistence | Contain rules |
| Crypto service | Primitives + bounded inputs | Touch the database |

The dependency direction is strictly downward. `AesGcmService` does not
know what HTTP is; `MessagingService` does not implement AES.

## The three security zones

`SecurityConfig` encodes exactly three zones:

1. **`/actuator/health`** — liveness probes only.
2. **Public:** `/api/v1/lab/**` (stateless demonstrations with no user
   data) plus `/api/v1/auth/register` and `/login` (the only ways to obtain
   a token, so they must be reachable anonymously).
3. **Authenticated:** everything else. Spring Security's resource-server
   filter verifies the bearer token per request (Nimbus); there is no HTTP
   session anywhere.

CSRF is disabled because there are no cookies — the token travels in the
`Authorization` header, which cross-site forms and images cannot set. The
classic CSRF vector is absent by construction rather than by configuration.

## The token pipeline

Tokens are issued and verified by the **standard Spring Security OAuth2
resource-server stack** (Nimbus JOSE+JWT — `spring-boot-starter-security-
oauth2-resource-server` was already on the classpath and is now the only
JWT code path). `JwtService.issueToken` signs with `MACSigner`; the
`JwtDecoder` bean (built by `JwtService.createDecoder()`, the single
construction site shared by production and tests) enforces on every
request:

- **Algorithm is fixed to HS256.** `alg=none` and algorithm-swapped tokens
  are rejected by the JOSE processor before any claim is read — the classic
  algorithm-confusion attack has no surface.
- **Issuer is validated** (`iss` = `cipherlab-api` by default, configurable
  via `JWT_ISSUER`), so tokens minted for another service are refused.
- **Expiry is validated** (`exp`) on every request.
- **The secret policy fails fast at startup**: missing/blank secret →
  refused; under 32 characters → refused; the publicly known development
  value → refused *unless* the dev profile explicitly allows it (the
  default lives only in `application-dev.yml`). Both refusals are proven as
  unit tests and by launching the packaged jar (`java -jar` exits 1 with an
  explanatory message).

The custom `JwtAuthenticationFilter` and its regex claim parser are gone;
a small converter maps verified claims onto the `AuthenticatedUser`
principal. The hand-rolled version had a real flaw — regex claim extraction
mangled usernames containing `,` or `}` — which is exactly why token
formats belong to libraries.

## Where the cryptography lives

**The server never holds a key that can decrypt user traffic.** This is the
central invariant, and it is enforced in three places:

- Identity keys store only the **public** half. A full database compromise
  yields no private material.
- `crypto_sessions` records lifecycle metadata — initiator, responder,
  suite, status, expiry — plus the **public** handshake material (both
  ephemeral SPKI public keys, both identity signatures, the identity key
  ids, and the transcript hash). No private keys, no derived secrets, no
  plaintext.
- The relay stores ciphertext and a nonce. It can route and deduplicate;
  it cannot read.

The lab endpoints are the deliberate exception in *form* (they encrypt and
decrypt on demand) but not in substance: they are stateless, hold no user
data, and are never invoked by the messaging client.

## The session handshake — when does `ACTIVE` mean anything?

`ACTIVE` is not a button press. A session must complete this signed
ephemeral ECDH handshake first (client logic in `frontend/src/lib/e2ee.ts`,
server verification in `MessagingService`, transcript definition in
`SessionTranscript`):

1. **Initiator** generates an *ephemeral* P-256 keypair in the browser and
   POSTs `{sessionId, suite, ephA, sigA, identityKeyId}` where
   `sigA = ECDSA-SHA256(identityPrivateKey_A,
   "cipherlab-session-v1|sid|conv|init|resp|suite|A:ephA")`. The session id
   is client-chosen so both parties can sign the same bytes. The server
   verifies the identity key belongs to the caller, is EC_P256 and not
   revoked, parses `ephA` as real P-256, and verifies `sigA` — any failure
   is 400 and no session exists.
2. **Responder** discovers the pending session, fetches its transcript
   material, and **verifies `sigA` against the initiator's published
   identity key client-side** — never trusting the server's word for who
   signed what. It then generates its own ephemeral, signs the *full*
   transcript (now `…|B:ephB`) with its identity key, and POSTs
   `{ephB, sigB, identityKeyId}` to `/activate`. The server re-verifies
   before status may become ACTIVE.
3. **Both clients** derive keys strictly locally: ECDH(ephA, ephB) →
   HKDF-SHA-256 (salt = session id bytes, two context-separated info
   labels `transcript|a2b` and `transcript|b2a`) → two directional
   AES-256-GCM keys. The server never sees ECDH output or derived keys.

Each message then uses a fresh 96-bit nonce with AAD
`sessionId|conversationId|senderId|sequenceNumber`, so envelopes are bound
to their position — relocation, replay and cross-session splicing all fail
authentication in the recipient's browser.

## Replay rejection

A replay is a previously-sent envelope re-submitted to the relay. Detection
rides the database, not application guesswork:

```sql
CREATE UNIQUE INDEX uq_messages_session_sender_seq
    ON messages (session_id, sender_id, sequence_number);
```

The service pre-checks for a clean `400 REPLAYED_MESSAGE`, and still catches
`DataIntegrityViolationException` so a concurrent double-submit cannot slip
through. **The index is the source of truth; the check is courtesy.** Note
the constraint is per-sender: two parties may legitimately use the same
sequence number, because each encrypts to the same session key from their
own counter.

The attack this stops matters as much as the mechanism: an attacker who
captures `pay me 100 coins` and re-submits it cannot make the relay accept
it twice, and the relay never needs to decrypt anything to know that.

## The audit trail, and why its writes have two timings

`audit_events` records security-relevant acts. Writing them correctly is
subtler than it looks — two bugs were caught by `AuditTrailTest` before the
design settled:

- **`REQUIRES_NEW` everywhere breaks registration.** A separate transaction
  suspends the caller, so the `USER_REGISTERED` row references a `users`
  row that has not committed yet → foreign key violation.
- **Writing inside the caller's transaction loses rejection evidence.** A
  replay rejection saves a row and then throws; the rollback erases exactly
  the row an operator needs.

`AuditService` therefore has two entry points:

- `record(...)` — for events alongside a **successful** change. Defers the
  write to after commit (via a `TransactionTemplate` in the callback,
  because the original `EntityManager` can no longer host a write once its
  transaction has completed), so foreign keys resolve and no phantom row
  survives a rollback.
- `recordSecurityEvent(...)` — for events **caused by a rejection**. Writes
  immediately in its own transaction so the evidence outlives the rollback.
  Safe because the entities it references were committed earlier.

Audit failures are logged and swallowed: losing a row is bad, but turning a
successful login into a 500 because the audit table hiccuped is worse. The
documented trade-off is that an attacker who can fault the audit table
reduces observability but cannot bypass authentication.

## Error contract

Every error — from any layer, including the security filter chain — is
shaped as:

```json
{ "code": "INVALID_CIPHERTEXT", "message": "...", "traceId": "..." }
```

Rules: no stack traces, no secrets, no plaintext ever leave the process.
401 and 403 are produced by the filter chain before a controller runs, so
`SecurityErrorResponses` writes the same body shape there; the MVC advice
covers everything else.

Two deliberate choices worth calling out:

- **Wrong credentials always answer the same body** (`INVALID_CREDENTIALS`,
  "Invalid username or password."). Distinguishing "no such user" from
  "wrong password" would hand out a username oracle.
- **Non-members get 404, not 403.** A membership probe must not be able to
  distinguish "no such conversation" from "not yours".

## Persistence

UUID primary keys are assigned by the application, never accepted from a
client. Schema changes go through Flyway; `ddl-auto: validate` means
Hibernate refuses to start against a schema it does not recognise, so a
migration that does not match the entities fails loudly at boot rather than
silently at runtime.

Entities use `LocalDateTime` with UTC values rather than `Instant`, because
Hibernate maps `Instant` to `TIMESTAMP WITH TIME ZONE` and the schema
declares `TIMESTAMP` — a mismatch `validate` would reject.

## Testing strategy

| Suite | What it proves |
|---|---|
| `AesGcmServiceTest` | Roundtrip incl. unicode/empty; tamper across ciphertext/tag/nonce/key/AAD; nonce freshness |
| `HashingServiceTest` | NIST SHA-2 vectors, RFC 4231 HMAC |
| `HkdfServiceTest` | RFC 5869 vectors |
| `SignatureServiceTest` | Sign/verify, tamper rejection, invalid-key fail-closed |
| `ToyDiffieHellmanServiceTest` | Textbook `p=23 → s=2`, bounds enforcement |
| `MitmSimulationTest` | Attack succeeds unauthenticated; substitution caught with signatures |
| `JwtServiceTest` | Standard-decoder pipeline: roundtrip, unicode, tampered payload/signature, `alg=none`, wrong secret, expiry, wrong issuer, malformed tokens, and the three secret-policy refusals (12 tests) |
| `AuthFlowTest` | Register→login→/me over the real filter chain; duplicate identity; oracle-free errors; hash never leaks |
| `IdentityKeyFlowTest` | Publish with independently recomputed fingerprint; rotation; revoke final; **key material parsed** (garbage, wrong curve, wrong modulus, type mismatch all rejected) |
| `MessagingFlowTest` | Full flow with a **real signed handshake**; replay rejected; lifecycle enforced; outsiders get 404; substituted ephemeral / wrong-key signature / bad transcript signature / revoked+foreign identity keys all rejected; malformed and oversized envelopes refused (13 tests) |
| `AuditTrailTest` | Auth and replay events are recorded, and carry no secrets |

MockMvc tests run against the **real security filter chain** with **real
tokens issued by the running service** — not test doubles — so the whole
JWT pipeline is exercised end to end.

The frontend adds a vitest suite (`npm test`, 11 tests) that proves the
browser half of the protocol on the same Web Crypto API the browser runs:
fingerprint parity with the server's computation, transcript sign/verify
(including substituted-ephemeral and wrong-key attacks), DER/raw signature
round-trips, directional-key cross-decrypt matrices, HKDF context
separation, AAD relocation, bit-flip tampering and nonce freshness.

## Known limits (v1)

- **Toy DH is intentionally not production crypto.** Inputs are bounded to
  512 bits specifically so the module *cannot* be reused for real traffic.
- **Sessions are two-party.** Group messaging would need per-member keys and
  a different replay constraint.
- **No key rotation for sessions.** A long-lived session keeps one key; a
  production protocol would ratchet.
- **Identity private keys live in browser memory** (with a user-held
  backup file for restore) — never localStorage, never the server. A lost
  backup means a new identity fingerprint your contact must re-verify.
- **Fingerprint verification is trust-on-first-use** unless users compare
  out of band as the UI instructs; nothing technically forces the
  comparison.
