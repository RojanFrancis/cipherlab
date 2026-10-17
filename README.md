# CipherLab

**Interactive Cryptography Laboratory & Secure Communication Platform**

> Learn the mathematics. Test the protocol. Observe the security failure. Verify the protection.

A security-engineering portfolio project: an interactive cryptography lab (Diffie–Hall man
calculations, AES-256-GCM tampering experiments, HMAC/signature demonstrations, a controlled
MITM simulation) plus a deliberately scoped two-user encrypted messaging prototype —
built as a Java 21 / Spring Boot modular monolith with a React + TypeScript frontend
and PostgreSQL.

## Stack

| Layer        | Technology                                   |
|--------------|----------------------------------------------|
| Backend      | Java 21, Spring Boot, Maven                  |
| API          | REST (`/api/v1`), Bean Validation, OpenAPI   |
| Security     | Spring Security, short-lived JWT (Week 3)    |
| Persistence  | Spring Data JPA, PostgreSQL, Flyway          |
| Frontend     | React, TypeScript, Vite                      |
| Testing      | JUnit 5, Mockito, Spring Boot Test, Testcontainers |
| Delivery     | Docker Compose, GitHub Actions CI            |

## Repository layout

```
cipherlab/
├── backend/          # Spring Boot API (Maven wrapper committed)
├── frontend/         # React + TypeScript (Vite)
├── docs/             # architecture, threat model, API examples
├── docker-compose.yml
└── README.md
```

Toy/crypto-lab code and the real secure-channel code are kept in **separate modules**.
A value produced by the toy Diffie–Hellman demonstration must never be usable as a key
by the messaging implementation.

## Day 1 setup

Prerequisites: Java 21, Git, Docker + Docker Compose, Node.js + npm.

```bash
# 1. Start PostgreSQL
cp .env.example .env          # then edit DB_PASSWORD
docker compose up -d db
docker compose ps             # wait until healthy

# 2. Run the backend
cd backend
./mvnw spring-boot:run        # API on http://localhost:8080

# 3. Verify
curl http://localhost:8080/actuator/health
# -> {"status":"UP"}
```

No Docker available (CI, restricted VM)? Use the H2-backed dev profile instead:

```bash
cd backend
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

## Day 1 status

- [x] Java 21 + Git verified
- [x] Spring Boot project generated (com.rojan.cipherlab, Maven wrapper committed)
- [x] React + TypeScript frontend scaffolded
- [x] PostgreSQL configured through Docker Compose (compose file authored; healthcheck included)
- [x] Flyway initial migration (`V1__initial_schema.sql`) — verified on dev profile
- [x] Health endpoint restricted to public access, all other routes authenticated
- [x] Initial commit created
- [x] This README with purpose + setup instructions

## Security notes (v1.0 scope)

- The database stores **identity metadata and ciphertext only** — never private keys,
  derived session keys or message plaintext.
- Passwords are hashed with an adaptive password-hashing algorithm (never plain SHA-256).
- `/api/v1/lab/**` endpoints are **educational demonstrations**; they are never used
  by the secure messaging path.
- The two-user messaging prototype is a documented prototype with a threat model,
  not a claim of production-grade end-to-end encryption.