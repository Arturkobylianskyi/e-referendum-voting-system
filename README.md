# E-Referendum System

> **Academic Prototype Notice:** This repository contains an educational and research simulation of an anonymous electronic referendum system developed as a diploma thesis project. It is not an official government voting platform and does not collect or process real personal identification numbers.

Full-stack web application implementing an anonymous online referendum system. The system solves the fundamental challenge of electronic voting — **verifying voter eligibility while preserving complete ballot secrecy** — by combining **Chaum's RSA Blind Signatures** (FOO / Sensus protocol) with a tamper-evident **Blockchain** ballot ledger stored in **PostgreSQL**.

## Key Features

- **External Identity & Role Management (Keycloak)** - Delegates user authentication and eligibility verification to an OAuth2/OIDC identity provider (`ADMIN` and `VOTER` roles) without storing sensitive personal data in the voting application.
- **Cryptographic Ballot Secrecy** - Voters blind their vote commitment in the browser before requesting an RSA blind signature from the `ElectionAdmin`, ensuring the administrator never sees the voter's choice.
- **Unlinkable Anonymous Ballot Submission** - The voter unblinds the RSA signature locally in the browser and submits the signed commitment to the public blockchain endpoint without any user token, separating *who voted* from *how they voted*.
- **Single-Click Voting & Auto-Tallying** - Ballots combine a salted SHA-256 commitment with a Tally RSA-encrypted opening payload. Once an administrator closes the polls, all ballots are automatically decrypted, verified against their commitments, and counted.
- **Tamper-Evident Multi-Referendum Blockchain** - Supports multiple concurrent referendums stored in PostgreSQL, with public SHA-256 hash-chain auditing (`isChainValid`).

## Tech Stack

- **Backend:** Java 25, Spring Boot 4.1.2 (Spring Web, Spring Data JPA, Spring Security OAuth2 Resource Server), Lombok, Maven
- **Database & Identity Provider:** PostgreSQL 18, Keycloak (Docker Compose)
- **Frontend:** React, Vite, Web Crypto API & native JavaScript `BigInt`
- **Testing:** JUnit Jupiter 6, Mockito

## Project Structure

```text
eReferendumTest/
├── docker-compose.yml               # PostgreSQL 18 and Keycloak containers
├── ereferendum-realm.json           # Auto-imported Keycloak realm, roles, and test accounts
├── pom.xml                          # Maven configuration (Spring Boot 4.1.2, Java 25)
├── src/
│   ├── main/java/ereferendum/
│   │   ├── config/                  # SecurityConfig (JWT role mapping & endpoint rules)
│   │   ├── controller/              # ReferendumController (REST API endpoints)
│   │   ├── crypto/                  # RsaKeys, BlindSignatureMath, VoteCommitment
│   │   ├── dto/                     # Request and response JSON records
│   │   ├── exception/               # GlobalExceptionHandler (HTTP status mapping)
│   │   ├── model/                   # JPA entities (Referendum, Block, VoterAuthorization)
│   │   ├── repository/              # Spring Data JPA repositories
│   │   ├── service/                 # ElectionAdmin, VotingBlockchain
│   │   └── EreferendumApplication.java
│   └── test/java/ereferendum/
│       └── FooProtocolSecurityTest.java
└── frontend/                        # React (Vite) web application
```

## REST API Overview

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/referendums` | Public | List all referendums |
| `GET` | `/api/referendums/{id}` | Public | Get referendum details, public RSA keys, blocks, and results |
| `POST` | `/api/referendums` | `ROLE_ADMIN` | Create a new referendum |
| `POST` | `/api/referendums/{id}/authorize` | `ROLE_VOTER` | Verify voter eligibility and issue an RSA blind signature |
| `POST` | `/api/referendums/{id}/ballots` | Public (Anonymous) | Submit an unblinded signed ballot to the blockchain |
| `POST` | `/api/referendums/{id}/close` | `ROLE_ADMIN` | Close polls, decrypt all ballots, and publish results |

## Running the Project

### 1. Environment Variables & Docker Containers
Create a `.env` file in the project root:
```properties
DB_NAME=ereferendum
DB_USER=postgres
DB_PASSWORD=password
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
```

Start PostgreSQL 18 and Keycloak:
```bash
docker compose up -d
```
Keycloak automatically imports `ereferendum-realm.json` on `http://localhost:8081` with pre-configured test accounts:
- **Admin (`ROLE_ADMIN`):** `admin` / `admin123`
- **Voters (`ROLE_VOTER`):** `voter1` / `voter123`, `voter2` / `voter123`

### 2. Backend (Spring Boot)
Run the Spring Boot server on `http://localhost:8080` via IntelliJ IDEA (`EreferendumApplication`) or Maven:
```bash
mvn spring-boot:run
```

### 3. Frontend (React)
Start the Vite development server on `http://localhost:5173`:
```bash
cd frontend
npm run dev
```

### 4. Unit & Security Tests
```bash
mvn test
```