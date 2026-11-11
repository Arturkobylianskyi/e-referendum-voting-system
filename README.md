# E-Referendum System

Core cryptographic and business logic for an anonymous online referendum system, developed as a diploma thesis project.

The system solves the fundamental challenge of electronic voting - **verifying voter eligibility while preserving complete ballot secrecy** - by combining **Chaum's RSA Blind Signatures** (FOO / Sensus protocol) with an immutable **Blockchain** ballot ledger.

## Key Features

- **Voter Eligibility Verification** - Validates PESEL numbers, age check on election day and prevents double registration.
- **Cryptographic Anonymity** - The Election Administrator authorizes voters using RSA blind signatures without ever seeing their vote choice.
- **Single-Click Voting** - Voters submit their sealed SHA-256 commitment along with an RSA-encrypted payload in a single step, eliminating the need to return after polls close.
- **Tamper-Evident Blockchain Ledger** - Ballots are stored in a hash-linked chain of blocks with public integrity auditing.
- **Automated Tallying** - Once polls close, the ballot box decrypts all ballots, verifies them against their commitments, and counts valid and invalid votes.

## Tech Stack

- **Java 25**
- **Maven**
- **JUnit Jupiter 6**

## Project Structure

- `ElectionAdmin.java` - Verifies voter eligibility via PESEL, blocks double voting, and issues RSA blind signatures.
- `VotingBlockchain.java` - Public ballot ledger and automatic tallying authority
- `Block.java` - Single block model storing a sealed ballot and its revealed status.
- `BlindSignatureMath.java` - Mathematical operations for RSA blinding, signing, unblinding, and verification.
- `VoteCommitment.java` - Salted SHA-256 commitment creation and RSA encryption/decryption of the ballot opening.
- `RsaKeys.java` - Record encapsulating RSA key pair generation.
- `PeselValidator.java` - PESEL checksum calculation, birthdate extraction across centuries, and age verification.
- `Main.java` - Console simulation of a complete referendum lifecycle.
- `FooProtocolSecurityTest.java` - Unit and security test suite covering protocol attacks and edge cases.

## How It Works (Overview)

1. **Authorization** - The voter seals their choice in a salted SHA-256 commitment, blinds it with a random factor, and sends it with their PESEL to the `ElectionAdmin` to obtain a blind signature.
2. **Anonymous Ballot Submission** - The voter unblinds the signature locally and submits the commitment, clean signature, and encrypted vote opening to the `VotingBlockchain` (without their PESEL).
3. **Reveal & Tally** - After polls close, the `VotingBlockchain` decrypts all ballot openings, verifies each vote against its original SHA-256 commitment, and computes the final results.

## Running the Project

Run the test suite:
```bash
mvn test
```

Run the console simulation:
```bash
mvn compile exec:java -Dexec.mainClass="Main"
```