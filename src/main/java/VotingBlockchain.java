import java.math.BigInteger;
import java.time.LocalDate;
import java.util.*;

public class VotingBlockchain {


    // Single block in the blockchain storing one sealed ballot
    public static class Block{
        public final int index;
        public final BigInteger commitmentX;
        public final BigInteger cleanSignature;
        public final String previousHash;
        public final String currentHash;

        // filled later during Phase 3 (Reveal)
        public String revealedCandidate = null;
        public String revealedSalt = null;

        public Block(int index, BigInteger commitmentX, BigInteger cleanSignature, String previousHash){
            this.index = index;
            this.commitmentX =commitmentX;
            this.cleanSignature = cleanSignature;
            this.previousHash = previousHash;
            this.currentHash = calculateHash();
        }

        // Computes SHA-256 hash of the block's immutable fields
        public String calculateHash(){
            String blockData = index + ":" +  commitmentX.toString(16) + ":" + cleanSignature.toString(16);
            return VoteCommitment.createCommitment(blockData, previousHash).toString(16);
        }
    }

    private final BigInteger adminModulsN;
    private final BigInteger adminPubExponentE;
    private final List<Block> chain = new ArrayList<>();
    private final Set<BigInteger> usedCommitments = new HashSet<>();

    public VotingBlockchain(BigInteger adminModulsN, BigInteger adminPubExponentE){
        this.adminModulsN = adminModulsN;
        this.adminPubExponentE = adminPubExponentE;
    }

    // Phase 2 (Commit) : Voter anonymously submits sealed commitment + unblinded Admin signature
    public int submitBallot(BigInteger commitmentX, BigInteger cleanSignature){
        // 1. Reject duplicate ballots
        if(usedCommitments.contains(commitmentX)){
            throw new SecurityException("Rejected: This ballot commitment is already on the blockchain");
        }

        // 2. Verify Admin's RSA signature using Utility #3
        boolean isSigValid = BlindSignatureMath.verifySignature(commitmentX, cleanSignature, adminPubExponentE, adminModulsN);
        if(!isSigValid){
            throw new SecurityException("Rejected: Invalid Admin RSA signature!");
        }

        // 3. Create new block linked to the previous block's hash
        int newIndex = chain.size();
        String prevHash = (newIndex == 0) ? "0000000000000000" : chain.get(newIndex - 1).currentHash;

        Block newBlock = new Block(newIndex, commitmentX, cleanSignature, prevHash);
        chain.add(newBlock);
        usedCommitments.add(commitmentX);

        return newIndex;
    }

    // Phase 3(Reveal) : Voter anonymously sends (blockIndex, candidate, salt) to open their ballot
    public void revealVote(int blockIndex, String candidate, String salt){
        if(blockIndex < 0 || blockIndex >= chain.size()){
            throw new IllegalArgumentException("Invalid block index: " + blockIndex);
        }

        Block block = chain.get(blockIndex);
        if(block.revealedCandidate != null){
            throw new SecurityException("Rejected: Block #" + blockIndex + " is already revealed!");
        }

        // Verify that SHA - 256(candidate + ":" + salt) matches the morning commitmentX using Utility #2;
        boolean isCommitmentMatching = VoteCommitment.verifyCommitment(block.commitmentX, candidate, salt);
        if(!isCommitmentMatching){
            throw new SecurityException("Rejected: Revealed vote or slat does not match commitment in Block #" + blockIndex);
        }

        block.revealedCandidate = candidate;
        block.revealedSalt = salt;
    }

    // Audit: Verifies that no block in the chain has been tampered with
    public boolean isChainValid(){
        for(int i = 0; i < chain.size(); i++){
            Block current = chain.get(i);

            // Check 1: Does the block's data still produce the exact same hash ?
            if(!current.currentHash.equals(current.calculateHash())){
                return false;
            }

            // Check 2: Does the block point to the exact hash of the previous block ?
            if(i > 0){
                Block previous = chain.get(i - 1);
                if(!current.previousHash.equals(previous.currentHash)){
                    return false;
                }
            }
        }

        return true;
    }

    // Phase 4 (Tally): Counts revealed votes and prints the public ledger
    public void printResult(){
        System.out.println("\n== Blockchain ledger audit (Chain Valid: " + isChainValid() + ") ==");

        Map<String, Integer> tally = new HashMap<>();

        for(Block b : chain){
            System.out.printf("Block #%d | PrevHash: %s... | BlockHash: %s... | Vote: %s%n",
                    b.index,
                    b.previousHash.substring(0, 8),
                    b.currentHash.substring(0, 8),
                    b.revealedCandidate != null ? b.revealedCandidate : "[SEALED]");

            if(b.revealedCandidate != null){
                tally.merge(b.revealedCandidate, 1, Integer::sum);
            }
        }

        System.out.println("\n=== Final election tally ===");
        tally.forEach((candidate, count) -> System.out.println(candidate + ": " + count + " vote(s)"));
    }

    public static void main(String[] args){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE());

        // Voter 1 prepares ballot for "Kandydat Nowak"
        String pesel1 = "99051512343";
        String pesel2 = "01292012272";
        String salt1 = VoteCommitment.generateSalt();
        String salt2 = VoteCommitment.generateSalt();

        BigInteger commit1 = VoteCommitment.createCommitment("Kandydat Nowak", salt1);
        BigInteger commit2 = VoteCommitment.createCommitment("Kandydat Nowak", salt2);


        // Phase 1: Get blind signature from Admin
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blinded1 = BlindSignatureMath.blind(commit1, maskB, admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig1 = admin.authorizeAndSign(pesel1, blinded1);
        BigInteger cleanSig1 = BlindSignatureMath.unblind(blindSig1, maskB, admin.getModulusN());

        BigInteger maskB2 = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blinded2 = BlindSignatureMath.blind(commit2, maskB2, admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig2 = admin.authorizeAndSign(pesel2, blinded2);
        BigInteger cleanSig2 = BlindSignatureMath.unblind(blindSig2, maskB2, admin.getModulusN());


        //Phase 2: Submit sealed ballot to Blockchain
        int blockIndex = blockchain.submitBallot(commit1, cleanSig1);
        System.out.println("Phase 2 (Before 20:00): Ballot added at Block #" + blockIndex);
        blockchain.printResult(); // vote is still sealed

        int blockIndex2 = blockchain.submitBallot(commit2, cleanSig2);
        System.out.println("Phase 2 (Before 20:00): Ballot added at Block #" + blockIndex2);
        blockchain.printResult(); // vote is still sealed

        // Phase 3: Reveal vote after 20:00
        blockchain.revealVote(blockIndex, "Kandydat Nowak", salt1);
        System.out.println("\n Phase 3 (After 20:00) : Ballot revealed!");
        blockchain.printResult(); // Now the vote is counted!

        blockchain.revealVote(blockIndex2, "Kandydat Nowak", salt2);
        System.out.println("\n Phase 3 (After 20:00) : Ballot revealed!");
        blockchain.printResult(); // Now the vote is counted!
    }
}
