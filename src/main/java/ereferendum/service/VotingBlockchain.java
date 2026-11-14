package ereferendum.service;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.RsaKeys;
import ereferendum.crypto.VoteCommitment;
import ereferendum.model.Block;
import ereferendum.model.Referendum;
import ereferendum.repository.BlockRepository;
import ereferendum.repository.ReferendumRepository;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Public ballot ledger and automatic tallying authority for the e-referendum.
 * Accepts anonymously submitted ballots signed by the ElectionAdmin, stores them in a hash-linked
 * chain of blocks in PostgreSQL, and decrypts all votes using its Tally RSA private key once polls close.
 */
@Service
public class VotingBlockchain {

    private final BigInteger adminModulus;
    private final BigInteger adminPublicExponent;

    // Key pair used for automatic ballot decryption after polls close
    private final RsaKeys tallyKeys = RsaKeys.generate();

    private final ReferendumRepository referendumRepository;
    private final BlockRepository blockRepository;

    public VotingBlockchain(ElectionAdmin admin, ReferendumRepository referendumRepository, BlockRepository blockRepository) {
        this.adminModulus = admin.getModulusN();
        this.adminPublicExponent = admin.getPubExponentE();
        this.referendumRepository = referendumRepository;
        this.blockRepository = blockRepository;
    }

    public BigInteger getTallyModulusN() {
        return tallyKeys.modulusN();
    }

    public BigInteger getTallyPubExponentE() {
        return tallyKeys.publicExponentE();
    }

    // Validates inputs and creates a new open referendum in the database
    public Referendum createReferendum(String title, String question, List<String> allowedAnswers) {
        if (title == null || title.isBlank() || question == null || question.isBlank()) {
            throw new IllegalArgumentException("Title and question cannot be blank");
        }
        validateAnswer(allowedAnswers);
        return referendumRepository.save(new Referendum(title, question, allowedAnswers));
    }

    // Ensures the referendum has at least two unique, non-blank answers
    private void validateAnswer(List<String> allowedAnswers) {
        if (allowedAnswers == null || allowedAnswers.size() < 2) {
            throw new IllegalArgumentException("Referendum needs at least 2 answers");
        }
        for (String answer : allowedAnswers) {
            if (answer == null || answer.isBlank() || answer.contains(":")) {
                throw new IllegalArgumentException("Invalid answer: " + answer);
            }
        }
        if (new HashSet<>(allowedAnswers).size() != allowedAnswers.size()) {
            throw new IllegalArgumentException("Answer must not repeat");
        }
    }

    public Referendum getReferendum(Long referendumId) {
        return referendumRepository.findById(referendumId)
                .orElseThrow(() -> new IllegalArgumentException("Referendum not found: " + referendumId));
    }

    public List<Referendum> getAllReferendums() {
        return referendumRepository.findAll();
    }

    public List<Block> getBlocks(Long referendumId) {
        return blockRepository.findByReferendumIdOrderByIndexAsc(referendumId);
    }

    // Validates commitment format and verifies Admin's RSA signature on the ballot
    private void verifyBallotSignature(BigInteger commitmentX, BigInteger cleanSignature) throws SecurityException {
        if (commitmentX == null || commitmentX.signum() <= 0 || commitmentX.bitLength() > 256) {
            throw new SecurityException("Rejected: commitment is not a valid SHA-256 hash");
        }

        if (cleanSignature == null
                || cleanSignature.compareTo(BigInteger.ONE) <= 0
                || cleanSignature.compareTo(adminModulus) >= 0) {
            throw new SecurityException("Rejected: signature out of range");
        }

        boolean isSigValid = BlindSignatureMath.verifySignature(commitmentX, cleanSignature, adminPublicExponent, adminModulus);
        if (!isSigValid) {
            throw new SecurityException("Rejected: Invalid Admin RSA signature!");
        }
    }

    // Verifies Admin's RSA signature on the commitment and appends the sealed ballot as a new block
    public int submitBallot(Long referendumId, BigInteger commitmentX, BigInteger cleanSignature, BigInteger encryptedOpening) throws SecurityException {
        Referendum referendum = getReferendum(referendumId);
        if (!referendum.isPollsOpen()) {
            throw new SecurityException("Rejected: polls are closed");
        }

        verifyBallotSignature(commitmentX, cleanSignature);

        if (blockRepository.existsByReferendumIdAndCommitmentX(referendumId, commitmentX)) {
            throw new SecurityException("Rejected: This ballot commitment is already on the blockchain");
        }

        List<Block> blocks = getBlocks(referendumId);
        int newIndex = blocks.size();
        String prevHash = (newIndex == 0) ? "0000000000000000" : blocks.get(newIndex - 1).currentHash;

        Block newBlock = new Block(referendum, newIndex, commitmentX, cleanSignature, encryptedOpening, prevHash);
        blockRepository.save(newBlock);

        return newIndex;
    }

    // Closes voting for the referendum and triggers automatic decryption of all its stored ballots
    public void closePollsAndRevealAll(Long referendumId) {
        Referendum referendum = getReferendum(referendumId);
        if (!referendum.isPollsOpen()) {
            throw new IllegalStateException("Polls are already closed");
        }

        referendum.closePolls();
        referendumRepository.save(referendum);

        List<Block> blocks = getBlocks(referendumId);
        for (Block block : blocks) {
            revealBlock(block, referendum.getAllowedAnswers());
        }
        blockRepository.saveAll(blocks);
    }

    // Decrypts a single ballot and verifies that the vote matches its original SHA-256 commitment
    private void revealBlock(Block block, List<String> allowedAnswers) {
        try {
            String decryptedPayload = VoteCommitment.decryptOpening(
                    block.encryptedOpening, tallyKeys.privateExponentD(), tallyKeys.modulusN()
            );

            String[] parts = decryptedPayload.split(":", 2);
            if (parts.length != 2) {
                block.markInvalid("corrupted payload format");
                return;
            }

            String candidate = parts[0];
            String salt = parts[1];

            if (!VoteCommitment.verifyCommitment(block.commitmentX, candidate, salt)) {
                block.markInvalid("decrypted vote does not match commitment");
                return;
            }

            if (!allowedAnswers.contains(candidate)) {
                block.markInvalid("answer not on the ballot");
                return;
            }

            block.reveal(candidate, salt);

        } catch (RuntimeException e) {
            block.markInvalid("could not decrypt or verify ballot");
        }
    }

    // Audits the referendum's blockchain by recalculating each block's hash and verifying previousHash links
    public boolean isChainValid(Long referendumId) {
        List<Block> blocks = getBlocks(referendumId);
        for (int i = 0; i < blocks.size(); i++) {
            Block current = blocks.get(i);

            if (!current.currentHash.equals(current.calculateHash())) {
                return false;
            }

            if (i > 0) {
                Block previous = blocks.get(i - 1);
                if (!current.previousHash.equals(previous.currentHash)) {
                    return false;
                }
            }
        }
        return true;
    }

    // Counts all valid revealed votes for each allowed referendum answer
    public Map<String, Integer> countVotes(Long referendumId) {
        Referendum referendum = getReferendum(referendumId);
        List<Block> blocks = getBlocks(referendumId);

        Map<String, Integer> tally = new LinkedHashMap<>();
        for (String answer : referendum.getAllowedAnswers()) {
            tally.put(answer, 0);
        }

        for (Block b : blocks) {
            if (b.revealedCandidate != null) {
                tally.merge(b.revealedCandidate, 1, Integer::sum);
            }
        }

        return tally;
    }

    // Returns the total number of ballots marked as invalid during decryption
    public int countInvalidBallots(Long referendumId) {
        int invalidCount = 0;
        for (Block b : getBlocks(referendumId)) {
            if (b.invalid) {
                invalidCount++;
            }
        }
        return invalidCount;
    }
}