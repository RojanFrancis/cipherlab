# CipherLab API Examples

Every example below was run against the packaged jar and pasted verbatim.
Base URL: `http://localhost:8080`.

Errors always share one shape:

```json
{ "code": "INVALID_CIPHERTEXT", "message": "...", "traceId": "8cd65669a5a042ef" }
```

---

## Lab (anonymous)

These endpoints hold no user data and require no token.

### Encrypt

```bash
curl -s -X POST localhost:8080/api/v1/lab/aes/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"hello cipherlab"}'
```

```json
{
  "algorithm": "AES/GCM/NoPadding",
  "key": "V23hKuALitYlEXyN4AqWxzZhLxCsf0LgowcJZwQj7qY=",
  "nonce": "6v4oARAqrArzctX2m",
  "ciphertext": "nJH0a+cdB8XdW2M=",
  "tag": "Y74UrosT3wnW1T1rWSIJgg==",
  "combined": "nJH0a+cdB8XdW2M=Y74UrosT3wnW1T1rWSIJgg==",
  "securityNote": "..."
}
```

`ciphertext` and `tag` are separated so the UI can tamper with each
independently; `combined` is the `ciphertext || tag` wire form real
libraries use.

### Decrypt a *tampered* ciphertext

Flip one bit of the tag and the whole thing fails closed — **no plaintext
is returned**:

```json
{ "code": "INVALID_CIPHERTEXT",
  "message": "The ciphertext could not be authenticated.",
  "traceId": "9f2c1d..." }
```

### Hash and HMAC

```bash
curl -s -X POST localhost:8080/api/v1/lab/hash \
  -H 'Content-Type: application/json' \
  -d '{"input":"The quick brown fox","algorithm":"SHA-256"}'
# {"algorithm":"SHA-256","digest":"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"}
```

### Diffie-Hellman (toy, textbook)

```bash
curl -s -X POST localhost:8080/api/v1/lab/diffie-hellman \
  -H 'Content-Type: application/json' \
  -d '{"p":"23","g":"5","alicePrivate":"6","bobPrivate":"15"}'
```

Both sides arrive at `2`. Inputs are bounded to 512 bits so the module
cannot be reused for real traffic.

### HKDF

```bash
curl -s -X POST localhost:8080/api/v1/lab/hkdf \
  -H 'Content-Type: application/json' \
  -d '{"ikm":"aW5wdXQga2V5IG1hdGVyaWFs","salt":"cmFuZG9tIHNhbHQ=","info":"app v1","outputLength":32}'
```

Returns `prkHex`, `outputHex`, and a step-by-step trace of extract → expand.
Change `info` and you get a different key: that binding is what stops
key-reuse bugs.

### MITM simulation

```bash
curl -s -X POST localhost:8080/api/v1/lab/mitm/simulate \
  -H 'Content-Type: application/json' -d '{"mode":"unauthenticated"}'
# malloryCanRead: true,  substitutionDetected: false

curl -s -X POST localhost:8080/api/v1/lab/mitm/simulate \
  -H 'Content-Type: application/json' -d '{"mode":"authenticated"}'
# malloryCanRead: false, substitutionDetected: true
```

---

## Auth

### Register

```bash
curl -s -X POST localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"correct horse battery"}'
```

```json
{ "id": "c17ea55c-fee4-4591-87c8-bd3f438a9795", "username": "alice",
  "email": "alice@example.com", "createdAt": "2026-10-20T05:58:29" }
```

A taken username answers **409**:

```json
{ "code": "DUPLICATE_USERNAME", "message": "That username is already taken.", "traceId": "..." }
```

### Login

```bash
curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery"}'
```

```json
{ "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.…",
  "tokenType": "Bearer", "expiresInSeconds": 3600,
  "user": { "id": "c17ea55c-…", "username": "alice", "email": "alice@example.com", "createdAt": "…" } }
```

Wrong password **and** unknown username return the identical body — no
username oracle:

```json
{ "code": "INVALID_CREDENTIALS", "message": "Invalid username or password.", "traceId": "..." }
```

### `/me` and the auth boundary

```bash
curl -s localhost:8080/api/v1/auth/me -H "Authorization: Bearer $TOKEN"
# {"id":"c17ea55c-…","username":"alice","email":"alice@example.com","createdAt":"…"}

curl -s localhost:8080/api/v1/auth/me
# {"code":"UNAUTHENTICATED","message":"A valid Bearer token is required for this endpoint","traceId":"…"}
```

A forged `alg=none` token gets the same 401:

```bash
curl -s localhost:8080/api/v1/auth/me -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiI…."
# 401 UNAUTHENTICATED
```

---

## Identity keys

```bash
curl -s -X POST localhost:8080/api/v1/identity/keys \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyType":"EC_P256","publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"}'
```

```json
{ "id": "19f0726b-…", "keyType": "EC_P256",
  "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…",
  "fingerprint": "56999a332fec3e803ae23cda09b8b345f98892fa66c591c54a0d90e6cde6b119",
  "keyVersion": 1, "revoked": false, "revokedAt": null }
```

The fingerprint is `SHA-256(publicKeyBytes)` in hex, **recomputed
server-side** — a client-supplied fingerprint would defeat the purpose.
Publishing a second key returns `keyVersion: 2`; rotation keeps history so
old signatures stay verifiable. Revocation sets `revokedAt` and never
deletes the row.

Peer lookup, the fingerprint-verification path:

```bash
curl -s localhost:8080/api/v1/identity/users/$USER_ID/keys -H "Authorization: Bearer $TOKEN"
```

---

## Messaging

### Create a conversation and a session

```bash
curl -s -X POST localhost:8080/api/v1/conversations \
  -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d "{\"partnerId\":\"$BOB_ID\"}"
# {"id":"f8fe1f5a-…","memberIds":["c17ea55c-…","4f8d2544-…"],"createdAt":"…"}

curl -s -X POST localhost:8080/api/v1/conversations/$CONV/sessions \
  -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d '{"suite":"X25519+HKDF-SHA256+AES-256-GCM"}'
# {"id":"b3dca0b4-…","status":"PENDING","expiresAt":null}
```

Relaying before activation is refused — the lifecycle is enforced:

```json
{ "code": "SESSION_NOT_ACTIVE", "message": "Session must be ACTIVE before relaying messages.", "traceId": "..." }
```

Only the responder can activate; the initiator gets **409 NOT_RESPONDER**:

```bash
curl -s -X POST localhost:8080/api/v1/sessions/$SESSION/activate \
  -H "Authorization: Bearer $BOB"
# {"id":"b3dca0b4-…","status":"ACTIVE","expiresAt":"2026-10-21T05:59:14"}
```

### Relay ciphertext, then replay it

```bash
ENVELOPE='{"sequenceNumber":7,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"aGVsbG8gY2lwaGVybGFi"}'

curl -s -X POST localhost:8080/api/v1/sessions/$SESSION/messages \
  -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' -d "$ENVELOPE"
# 201 — stored. The server cannot read a byte of it.

curl -s -X POST localhost:8080/api/v1/sessions/$SESSION/messages \
  -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' -d "$ENVELOPE"
# 400 {"code":"REPLAYED_MESSAGE","message":"This (session, sender, sequence) has already been relayed.","traceId":"…"}
```

The rejection comes from the unique index on
`(session_id, sender_id, sequence_number)` — the server detects the replay
**without decrypting anything**. The constraint is per-sender, so Bob may
legitimately submit the same sequence number:

```bash
curl -s -X POST localhost:8080/api/v1/sessions/$SESSION/messages \
  -H "Authorization: Bearer $BOB" -H 'Content-Type: application/json' -d "$ENVELOPE"
# 201
```

### Membership is not probe-able

A non-member asking for history — or for a session that does not exist —
gets the same answer:

```bash
curl -s localhost:8080/api/v1/conversations/$CONV/messages -H "Authorization: Bearer $MALLORY"
# {"code":"NOT_FOUND","message":"The requested resource was not found.","traceId":"…"}
```

History returns envelopes only:

```json
[ { "id": "8e4ca2bf-…", "sequenceNumber": 7, "nonce": "AAAAAAAAAAAAAAAA",
    "ciphertext": "aGVsbG8gY2lwaGVybGFi", "senderId": "c17ea55c-…", "createdAt": "…" } ]
```
