# CipherLab Threat Model

Scope: the v1 backend and its messaging relay. This document names what the
system defends against, what it deliberately does not, and where a security
decision was a trade-off rather than a free win.

## Assets

| Asset | Where it lives | Consequence if compromised |
|---|---|---|
| Password hashes | `users.password_hash` (BCrypt) | Offline cracking → account takeover |
| Access tokens | Client `localStorage`, 1 h TTL | Impersonation until expiry |
| Identity **private** keys | **Client only — never the server** | Identity forgery, MITM capability |
| Identity public keys | `identity_keys` | Key substitution → traffic readable |
| Ciphertext + nonces | `messages` | Offline attack; no plaintext exposure |
| Session metadata | `crypto_sessions` | Social graph, timing, membership |

The absence of a row is itself a design statement: there is no column
anywhere that can decrypt user traffic.

## Adversaries

**A1 — Network attacker.** Can observe and modify traffic in transit.
*Defence:* TLS is assumed at the transport layer (out of scope for this
project but mandatory in deployment). Inside the application, ciphertext is
authenticated with GCM so tampering is detectable by the *recipient*, not
just the transport.

**A2 — Curious or compromised server operator.** Can read the database and
the process.
*Defence:* the operator holds no key that decrypts traffic. Identity private
keys never reach the server; sessions store metadata only. The operator can
still mount a **key-substitution attack** (A4) — this is a real, documented
limit, and the fingerprint feature exists precisely so users can detect it
out of band.

**A3 — Authenticated malicious user.** Has a valid account.
*Defences, each with the test that pins it:*
- Cannot read or write conversations they are not a member of → **404**
  (`MessagingFlowTest.nonMemberRejectedWith404`). No membership oracle.
- Cannot replay their own captured envelope → **400 REPLAYED_MESSAGE**
  (`replayIsRejectedWith400`). The unique index makes it unstorable.
- Cannot relay on a `PENDING` or expired session → **409**.
- Cannot revoke another user's key → **404** (`cannotRevokeForeignKey`).
- Cannot activate a session they initiated → **409 NOT_RESPONDER**. A
  session needs two parties to exist.

**A4 — Key-substitution / MITM attacker.** Controls the directory that maps
users to public keys.
*Defence:* fingerprints. The server recomputes
`SHA-256(publicKeyBytes)` on publish — a client-supplied fingerprint would
defeat the purpose. Users compare fingerprints out of band, a channel the
attacker does not control. `MitmSimulation` demonstrates both outcomes: the
identical attack succeeds unauthenticated and fails once signatures bind
identities to ephemeral keys.

**A5 — Token forger.** Tries to mint a token without the signing secret.
*Defences:* `alg=none` rejected before any crypto runs; signature compared
in constant time; expiry checked after the signature (`JwtServiceTest`).
The secret is refused at startup if under 32 characters, so a weak
deployment cannot boot by accident.

**A6 — Unauthenticated prober.** Enumerates endpoints.
*Defence:* everything outside the three public zones answers **401
UNAUTHENTICATED** with a consistent JSON body.

## Trust boundaries

```
[ browser ]  ── TLS ──  [ Spring Boot ]  ── SQL  ──  [ PostgreSQL ]
   owns: private keys       owns: nothing that       owns: ciphertext,
   owns: session keys         decrypts traffic         metadata, hashes
```

Two boundaries are enforced in code rather than assumed:
- The `Authorization` header is the only credential; there is no session
  cookie, so CSRF is structurally impossible.
- The API never accepts a client-supplied user id for any write — the
  principal comes from the verified token, so a client cannot claim to be
  someone else by editing a request field.

## Non-goals (v1)

These are omissions, not oversights. Each would be a real vulnerability if
claimed but is honest as a stated limit:

- **No TLS termination, rate limiting, or account lockout.** A production
  deployment needs all three; login is a brute-force target.
- **No forward secrecy.** Sessions use one key for their lifetime; a
  later-compromised key decrypts all recorded traffic under that session.
  A ratchet (X3DH + Double Ratchet) is the fix and the natural v2.
- **No group messaging.** The replay constraint is `(session, sender,
  sequence)`, which is correct for two parties only.
- **No key-ceremony UX.** Fingerprints are exposed in the UI but the app
  does not yet *force* a user to verify one before encrypting.
- **Tokens in `localStorage`.** Chosen so the JWT is inspectable in DevTools
  for teaching. An httpOnly cookie is the right call for a real deployment;
  the trade-off is CSRF, which then needs explicit handling.

## Security-relevant trade-offs

| Decision | Cost | Why it was taken |
|---|---|---|
| 404 instead of 403 for non-members | Legitimate users get a confusing "not found" | Membership must not be probe-able |
| Identical login error for bad user vs bad password | Worse UX for typos | No username oracle |
| Audit failures swallowed, not propagated | A broken audit table loses rows silently | A successful login must not become a 500 |
| BCrypt cost 10 | ~100 ms per login | Deliberate: password hashing should be slow |
| Hand-rolled JWT | We battle-tested it with 9 unit tests | In a *teaching* codebase, visible beats convenient |
| Toy DH bounded to 512 bits | Cannot be reused for real traffic | Intentional — the bound is the safeguard |

## What an attacker learns from any single response

This is the question the API answers uniformly:

- A successful encrypt: the algorithm, and lengths. Never the key's
  provenance.
- A failed decrypt: that the ciphertext did not authenticate. Never partial
  plaintext — `AuthenticationFailedException` maps to 400 with a generic
  message.
- A 4xx/5xx: a code, a human message, a traceId. Never a stack trace,
  never a token, never a hash.
- An audit row: an actor id, an event type, a resource id. Never a token
  (`AuditTrailTest.auditRowsCarryNoSecrets`).
