# E-Voting System (FOO / Sensus Protocol + Blockchain)

## System Roles
- **Voter**: Seals the vote in a salted SHA-256 hash, blinds it, gets Admin's signature, encrypts the opening payload with the Blockchain's Tally Public Key, and submits everything to the Blockchain in a single step.
- **Administrator (`ElectionAdmin`)**: Validates the voter's Polish PESEL (checksum + 18+ age), blocks double voting, and signs the blinded hash using RSA.
- **Blockchain (`VotingBlockchain`)**: Verifies Admin's RSA signature, stores sealed ballots, and after polls close, automatically decrypts and verifies all ballots using its Tally Private Key.

---

## Step-by-Step Algorithm

### Phase 1: Registration & Blind Signature
1. **Commit**: Voter chooses a candidate $v$, generates a random 256-bit salt $r$, and computes the vote hash:
   $$x = \text{SHA-256}(v \parallel \text{":"} \parallel r)$$
2. **Blind**: Voter generates a random secret mask $b$ ($\gcd(b, N) = 1$) and masks the hash using Admin's public key $(e, N)$:
   $$M_{\text{blind}} = (x \cdot b^e) \bmod N$$
3. **Sign**: Voter sends $(\text{PESEL}, M_{\text{blind}})$ to Admin. Admin validates the PESEL, marks it as used, and signs the masked hash with private key $d$:
   $$S_{\text{blind}} = (M_{\text{blind}})^d \bmod N$$
4. **Unblind**: Voter removes the mask $b$ locally to get a clean RSA signature on $x$:
   $$S_{\text{clean}} = (S_{\text{blind}} \cdot b^{-1}) \bmod N = x^d \pmod N$$

### Phase 2: Single-Click Anonymous Voting
1. Voter encrypts the opening payload $M = (v \parallel \text{":"} \parallel r)$ using the Blockchain's Tally Public Key $(e_{\text{tally}}, N_{\text{tally}})$:
   $$C_{\text{open}} = M^{e_{\text{tally}}} \bmod N_{\text{tally}}$$
2. Voter anonymously sends $(x, S_{\text{clean}}, C_{\text{open}})$ to the Blockchain (without PESEL) and goes offline.
3. Blockchain verifies Admin's signature using public key $(e, N)$:
   $$(S_{\text{clean}})^e \bmod N == x$$
4. If valid, Blockchain saves $(x, S_{\text{clean}}, C_{\text{open}})$ in a new `Block` linked to `previousHash` and returns `blockIndex`. Votes remain sealed while polls are open.

### Phase 3: Automatic Reveal & Tally (After Polls Close)
1. Once polls close, `closePollsAndRevealAll()` is triggered on the Blockchain (no further action required from the Voter).
2. For each block, Blockchain decrypts $C_{\text{open}}$ using its Tally Private Key $d_{\text{tally}}$:
   $$M = (C_{\text{open}})^{d_{\text{tally}}} \bmod N_{\text{tally}} \implies (v \parallel \text{":"} \parallel r)$$
3. Blockchain verifies integrity by checking if $\text{SHA-256}(v \parallel \text{":"} \parallel r)$ matches $x$ stored in the block.
4. If matched, the vote $v$ is unlocked and added to the final tally.

---

## Project Files
- `PeselValidator.java` — PESEL checksum and 18+ age validation.
- `VoteCommitment.java` — Salted SHA-256 commitment creation, verification, and RSA opening encryption/decryption.
- `BlindSignatureMath.java` — RSA blinding, signing, unblinding, and verification math.
- `ElectionAdmin.java` — PESEL registration and RSA blind signing service.
- `VotingBlockchain.java` — Blockchain ledger (`submitBallot`, `closePollsAndRevealAll`, `isChainValid`).
- `Main.java` — Full election simulation.
- `FooProtocolSecurityTest.java` — JUnit 5 security tests.

---

## Protocol Workflow Diagram

```text
+-------------------+              +------------------------+              +------------------------+
|       VOTER       |              | ELECTION ADMINISTRATOR |              |   BLOCKCHAIN LEDGER    |
+-------------------+              +------------------------+              +------------------------+
          |                                    |                                       |
          | 1. Generate salt 'r'               |                                       |
          |    x = SHA256(vote : r)            |                                       |
          |    BlindedMsg = x * (b^e) mod N    |                                       |
          |                                    |                                       |
          |--- (PESEL, BlindedMsg) ----------->|                                       |
          |                                    | 2. Validate PESEL (checksum & 18+)    |
          |                                    |    Check PESEL not already used       |
          |                                    |    BlindSig = (BlindedMsg)^d mod N    |
          |<-- (BlindSig) ---------------------|                                       |
          |                                    |                                       |
          | 3. Unblind signature locally:      |                                       |
          |    CleanSig = BlindSig * b^-1 mod N|                                       |
          |    (Result equals x^d mod N)       |                                       |
          |                                    |                                       |
          |=============[ ANONYMOUS CHANNEL / PHASE 2: SINGLE-CLICK VOTE ]=============|
          |                                    |                                       |
          | 4. Encrypt opening locally:        |                                       |
          |    C_open = (vote:r)^e_tally mod N |                                       |
          |                                    |                                       |
          |--- (x, CleanSig, C_open) ----------+-------------------------------------->|
          |    [NO PESEL! Voter goes offline]  |                                       | 5. Verify (CleanSig)^e == x
          |                                    |                                       |    Append Block #idx to Chain
          |<-- (Block Index #idx) -------------+---------------------------------------|
          |                                    |                                       |
          |==============[ AFTER POLLS CLOSE / PHASE 3: AUTO-REVEAL ]==================|
          |                                    |                                       |
          |    (No voter action needed)        |                                       | 6. Decrypt C_open with d_tally:
          |                                    |                                       |    (vote:r) = C_open^d_tally
          |                                    |                                       | 7. Verify SHA256(vote:r) == x
          |                                    |                                       |    Unlock ballot & count vote
```