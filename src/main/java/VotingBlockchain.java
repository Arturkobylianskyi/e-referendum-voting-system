import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class VotingBlockchain {


    // Single block in the blockchain storing one sealed ballot
    public static class Block{
        public final int index;
        public final BigInteger commitmentX;
        public final BigInteger cleanSignature;
        public final BigInteger encryptedOpening;
        public final String previousHash;
        public final String currentHash;

        // filled later during Phase 3 (Reveal)
        public String revealedCandidate = null;
        public String revealedSalt = null;

        public Block(int index, BigInteger commitmentX, BigInteger cleanSignature, BigInteger encryptedOpening, String previousHash){
            this.index = index;
            this.commitmentX =commitmentX;
            this.cleanSignature = cleanSignature;
            this.encryptedOpening = encryptedOpening;
            this.previousHash = previousHash;
            this.currentHash = calculateHash();
        }

        // Computes SHA-256 hash of the block's immutable fields
        public String calculateHash() {
            String blockData = index + ":" + commitmentX.toString(16) + ":" + cleanSignature.toString(16) + ":" + encryptedOpening.toString(16);
            return VoteCommitment.createCommitment(blockData, previousHash).toString(16);
        }
    }

    private final BigInteger adminModulsN;
    private final BigInteger adminPubExponentE;

    // Blockchain's own key pair for time-locked automatic opening after referendum
    private final BigInteger tallyModulusN;
    private final BigInteger tallyPubExponentE;
    private final BigInteger tallyPrivExponentD;

    private final List<Block> chain = new ArrayList<>();
    private final Set<BigInteger> usedCommitments = new HashSet<>();

    public VotingBlockchain(BigInteger adminModulsN, BigInteger adminPubExponentE) throws RuntimeException{
        this.adminModulsN = adminModulsN;
        this.adminPubExponentE = adminPubExponentE;

        try{
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();

            this.tallyModulusN = pub.getModulus();
            this.tallyPubExponentE = pub.getPublicExponent();
            this.tallyPrivExponentD = priv.getPrivateExponent();
        } catch (Exception e){
            throw new RuntimeException("Failed to initialize Tally RSA keys", e);
        }
    }

    public BigInteger getTallyModulusN(){
        return tallyModulusN;
    }

    public BigInteger getTallyPubExponentE(){
        return tallyPubExponentE;
    }

    public List<Block> getChain(){
        return chain;
    }

    // Phase 2 Voter anonymously submits sealed commitment + unblinded Admin signature
    public int submitBallot(BigInteger commitmentX, BigInteger cleanSignature, BigInteger encryptedOpening) throws SecurityException{
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

        Block newBlock = new Block(newIndex, commitmentX, cleanSignature, encryptedOpening, prevHash);
        chain.add(newBlock);
        usedCommitments.add(commitmentX);

        return newIndex;
    }

    // Phase 3(Reveal) : Voter anonymously sends (blockIndex, candidate, salt) to open their ballot
    public void closePollsAndRevealAll(){
        for(Block block : chain){
            if(block.revealedCandidate != null){
                continue;
            }

            // 1. Decrypt "candidate:salt" using Tally Private Key
            String decryptedPayload = VoteCommitment.decryptOpening(
                    block.encryptedOpening, tallyPrivExponentD, tallyModulusN
            );
            String[] parts = decryptedPayload.split(":", 2);
            if(parts.length !=2 ){
                throw new SecurityException("Corrupted payload format in Block #" + block.index);
            }

            String candidate = parts[0];
            String salt = parts[1];

            // 2. Verify that decrypted candidate + salt matches the morning commitmentX
            boolean isMatching = VoteCommitment.verifyCommitment(block.commitmentX, candidate, salt);
            if(!isMatching){
                throw new SecurityException("Integrity failure: Decrypted vote does not match commitmentX in Block #" + block.index);
            }

            block.revealedCandidate = candidate;
            block.revealedSalt = salt;

        }
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
        System.out.println("\nBlockchain ledger audit (Chain Valid: " + isChainValid() + ")");

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

        System.out.println("\nFinal election tally");
        if(tally.isEmpty()){
            System.out.println("No votes revealed yet (Polls are still open).");
        }else{
            tally.forEach((candidate, count) -> System.out.println(candidate + ": " + count + " vote(s)"));
        }
    }

}
