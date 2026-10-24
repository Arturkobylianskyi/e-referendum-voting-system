# E-Voting System (FOO Protocol + Blockchain)

## System Roles
* **Voter**: Seals the vote in a salted SHA-256 hash, blinds it, gets Admin's signature, and submits it to the Blockchain.
* **Administrator (`ElectionAdmin`)**: Validates the voter's Polish PESEL (checksum + 18+ age), blocks double voting, and signs the blinded hash using RSA.
* **Blockchain (`VotingBlockchain`)**: Verifies Admin's RSA signature, stores sealed votes (`Commit`), verifies opened votes (`Reveal`), and counts the results.

---

## Step-by-Step Algorithm

### Phase 1: Registration & Blind Signature (08:00 – 20:00)
1. **Commit**: Voter chooses a candidate $v$, generates a random 256-bit salt $r$, and computes the vote hash:
   $$x = \text{SHA-256}(v \parallel \text{":"} \parallel r)$$
2. **Blind**: Voter generates a random secret mask $b$ ($\gcd(b, N) = 1$) and masks the hash using Admin's public key $(e, N)$:
   $$M_{\text{blind}} = (x \cdot b^e) \bmod N$$
3. **Sign**: Voter sends $(\text{PESEL}, M_{\text{blind}})$ to Admin. Admin validates the PESEL, marks it as used, and signs the masked hash with private key $d$:
   $$S_{\text{blind}} = (M_{\text{blind}})^d \bmod N$$
4. **Unblind**: Voter removes the mask $b$ locally to get a clean RSA signature on $x$:
   $$S_{\text{clean}} = (S_{\text{blind}} \cdot b^{-1}) \bmod N = x^d \pmod N$$

### Phase 2: Anonymous Voting — Commit (08:00 – 20:00)
1. Voter anonymously sends $(x, S_{\text{clean}})$ to the Blockchain (without PESEL).
2. Blockchain verifies Admin's signature using public key $(e, N)$:
   $$(S_{\text{clean}})^e \bmod N == x$$
3. If valid, Blockchain saves $(x, S_{\text{clean}})$ in a new `Block` linked to `previousHash` and returns `blockIndex`. Votes remain hidden until 20:00.

### Phase 3: Opening Votes — Reveal (After 20:00)
1. Voter anonymously sends $(\text{blockIndex}, v, r)$ to the Blockchain.
2. Blockchain checks if $\text{SHA-256}(v \parallel \text{":"} \parallel r)$ matches $x$ stored in `Block #blockIndex`.
3. If matched, the vote $v$ is unlocked and added to the final tally.

---

## Project Files
* `PeselValidator.java` — PESEL checksum and 18+ age validation.
* `VoteCommitment.java` — Salted SHA-256 hash creation and verification.
* `BlindSignatureMath.java` — RSA blinding, signing, unblinding, and verification math.
* `ElectionAdmin.java` — PESEL registration and RSA blind signing service.
* `VotingBlockchain.java` — Blockchain ledger (`submitBallot`, `revealVote`, `isChainValid`).
* `Main.java` — Full election simulation.
* `FooProtocolSecurityTest.java` — JUnit 5 security tests.
## 4. Step-by-Step Protocol Workflow (4 Phases)

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
          |===================[ ANONYMOUS CHANNEL / PHASE 2: COMMIT ]=================|
          |                                    |                                       |
          |--- (x, CleanSig) [NO PESEL!] ------+-------------------------------------->|
          |                                    |                                       | 4. Verify (CleanSig)^e == x
          |                                    |                                       |    Append Block #idx to Chain
          |<-- (Block Index #idx) -------------+---------------------------------------|
          |                                    |                                       |
          |===================[ AFTER POLLS CLOSE / PHASE 3: REVEAL ]==================|
          |                                    |                                       |
          |--- (Block #idx, vote, salt 'r') ---+-------------------------------------->|
          |                                    |                                       | 5. Verify SHA256(vote:r) == x
          |                                    |                                       |    Unlock ballot & count vote
```
