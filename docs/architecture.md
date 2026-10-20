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
   ├── security      JWT (hand-rolled HS256), filter chain, 401/403 bodies
   ├── lab           six educational endpoints — no auth, no user data
   ├── auth          register / login (BCrypt), /me
   ├── identity      public key registry + fingerprints
   ├── messaging     conversations → sessions → ciphertext relay
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
3. **Authenticated:** everything else. The JWT filter verifies the bearer
   token per request; there is no HTTP session anywhere.

CSRF is disabled because there are no cookies — the token travels in the
`Authorization` header, which cross-site forms and images cannot set. The
classic CSRF vector is absent by construction rather than by configuration.

## The token pipeline

Tokens are issued by a hand-rolled HS256 implementation (`JwtService`)
rather than a library, so every step is auditable in a codebase whose
purpose is teaching. Three properties are enforced:

- **Algorithm confusion is impossible.** The `alg` header must be exactly
  `HS256`; `none` or a swapped algorithm is rejected before any crypto
  runs. This is the classic `alg=none` attack.
- **Constant-time verification.** `MessageDigest.isEqual` compares MACs,
  avoiding the timing side channel of `String.equals`.
- **Expiry is checked after the signature.** A forged `exp` cannot survive
  a bad signature.

Verification order in `JwtService.verify` is deliberate:
format → algorithm → signature → claims. Claims are only parsed once the
signature has proven they are trustworthy.

## Where the cryptography lives

**The server never holds a key that can decrypt user traffic.** This is the
central invariant, and it is enforced in three places:

- Identity keys store only the **public** half. A full database compromise
  yields no private material.
- `crypto_sessions` records lifecycle metadata — initiator, responder,
  suite, status, expiry. No derived secrets, no plaintext.
- The relay stores ciphertext and a nonce. It can route and deduplicate;
  it cannot read.

The lab endpoints are the deliberate exception in *form* (they encrypt and
decrypt on demand) but not in substance: they are stateless, hold no user
data, and are never invoked by the messaging client.

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
| `JwtServiceTest` | Roundtrip, tampered payload/signature, `alg=none`, wrong secret, expiry |
| `AuthFlowTest` | Register→login→/me over the real filter chain; duplicate identity; oracle-free errors; hash never leaks |
| `IdentityKeyFlowTest` | Publish with independently recomputed fingerprint; rotation; revoke is final |
| `MessagingFlowTest` | Full flow; replay rejected; lifecycle enforced; outsiders get 404 |
| `AuditTrailTest` | Auth and replay events are recorded, and carry no secrets |

MockMvc tests run against the **real security filter chain** with **real
tokens issued by the running service** — not test doubles — so the whole
JWT pipeline is exercised end to end.

## Known limits (v1)

- **Toy DH is intentionally not production crypto.** Inputs are bounded to
  512 bits specifically so the module *cannot* be reused for real traffic.
- **Sessions are two-party.** Group messaging would need per-member keys and
  a different replay constraint.
- **No key rotation for sessions.** A long-lived session keeps one key; a
  production protocol would ratchet.
- **The messaging UI shows a Base64 envelope, not Web Crypto.** The
  server-side contract is what the UI demonstrates; client-side ECDH +
  HKDF + AES-GCM in the browser is the natural next milestone.
