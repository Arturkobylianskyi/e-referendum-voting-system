import java.math.BigInteger;
import java.util.*;

public class VotingBlockchain {

    private final BigInteger adminModulus;
    private final BigInteger adminPublicExponent;

    // Blockchain's own key pair for time-locked automatic opening after referendum
    private final BigInteger tallyModulusN;
    private final BigInteger tallyPubExponentE;
    private final BigInteger tallyPrivExponentD;

    private final List<Block> chain = new ArrayList<>();
    private final Set<BigInteger> usedCommitments = new HashSet<>();
    private  boolean pollsOpen = true;
    private final List<String> allowedAnswers;

    public VotingBlockchain(BigInteger adminModulus, BigInteger adminPublicExponent, List<String> allowedAnswers){
        validateAnswer(allowedAnswers);

        this.allowedAnswers = List.copyOf(allowedAnswers);
        this.adminModulus = adminModulus;
        this.adminPublicExponent = adminPublicExponent;

        RsaKeys tallyKeys = RsaKeys.generate();
        this.tallyModulusN = tallyKeys.modulsN();
        this.tallyPubExponentE = tallyKeys.publicExponentE();
        this.tallyPrivExponentD = tallyKeys.privateExponentD();
    }

    private void validateAnswer(List<String> allowedAnswers){
        if(allowedAnswers == null || allowedAnswers.size() < 2){
            throw new IllegalArgumentException("Referendum needs at least 2 answers");
        }
        for(String answer : allowedAnswers){
            if(answer == null || answer.isBlank() || answer.contains(":")){
                throw new IllegalArgumentException("Invalid answer: " + answer);
            }
        }
        if(new HashSet<>(allowedAnswers).size() != allowedAnswers.size()){
            throw new IllegalArgumentException("Answer must not repeat");
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

    public boolean isPollsOpen(){
        return pollsOpen;
    }

    // Phase 2 Voter anonymously submits sealed commitment + unblinded Admin signature
    public int submitBallot(BigInteger commitmentX, BigInteger cleanSignature, BigInteger encryptedOpening) throws SecurityException{

        if(!pollsOpen){
            throw new SecurityException("Rejected: polls are closed");
        }

        // Commitment must look like a real SHA-256 hash
        if(commitmentX == null || commitmentX.signum() <= 0 || commitmentX.bitLength() > 256){
            throw new SecurityException("Rejected: commitment is not a valid SHA-256 hash");
        }

        if(cleanSignature == null
            || cleanSignature.compareTo(BigInteger.ONE) <= 0
            || cleanSignature.compareTo(adminModulus) >= 0){
            throw new SecurityException("Rejected: signature out of range");
        }

        // 1. Reject duplicate ballots
        if(usedCommitments.contains(commitmentX)){
            throw new SecurityException("Rejected: This ballot commitment is already on the blockchain");
        }

        // 2. Verify Admin's RSA signature using Utility #3
        boolean isSigValid = BlindSignatureMath.verifySignature(commitmentX, cleanSignature, adminPublicExponent, adminModulus);
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
        if(!pollsOpen){
            throw new IllegalStateException("Polls are already closed");
        }
        pollsOpen = false;

        for(Block block : chain){
            try{
                // 1. Decrypt candidate:salt using Tally Private Key
                String decryptedPayload = VoteCommitment.decryptOpening(
                        block.encryptedOpening, tallyPrivExponentD, tallyModulusN
                );

                String[] parts = decryptedPayload.split(":", 2);
                if(parts.length != 2){
                    block.markInvalid("corrupted payload format");
                    continue;
                }

                String candidate = parts[0];
                String salt = parts[1];

                // 2. Decrypted candidate + salt must match commitmentX
                if(!VoteCommitment.verifyCommitment(block.commitmentX, candidate, salt)){
                    block.markInvalid("decrypted vote does not match commitment");
                    continue;
                }

                if(!allowedAnswers.contains(candidate)){
                    block.markInvalid("answer not on the ballot");
                    continue;
                }

                block.reveal(candidate, salt);


            } catch (RuntimeException e){
                block.markInvalid("could not decrypt or verify ballot");
            }

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

        Map<String, Integer> tally = new LinkedHashMap<>();
        for(String answer : allowedAnswers){
            tally.put(answer, 0);
        }
        int invalidCount = 0;

        for(Block b : chain){
            System.out.printf("Block #%d | PrevHash: %s... | BlockHash: %s... | Vote: %s%n",
                    b.index,
                    b.previousHash.substring(0, 8),
                    b.currentHash.substring(0, 8),
                    b.formatStatus());

            if(b.invalid){
                invalidCount++;
            }

            if(b.revealedCandidate != null){
                tally.merge(b.revealedCandidate, 1, Integer::sum);
            }
        }

        System.out.println("\nFinal referendum result");
        if(pollsOpen){
            System.out.println("No votes revealed yet (Polls are still open).");
        }else{
            tally.forEach((answer, count) -> System.out.println(answer + ": " + count + " vote(s)"));
        }
        System.out.println("Invalid ballots: " + invalidCount);
    }

}
