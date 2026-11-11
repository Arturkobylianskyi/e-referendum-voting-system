package ereferendum.service;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.RsaKeys;
import ereferendum.crypto.VoteCommitment;
import ereferendum.model.Block;

import java.math.BigInteger;
import java.util.*;

/**
 * Public ballot ledger and automatic tallying authority for the e-referendum.
 * Accepts anonymously submitted ballots signed by the ereferendum.service.ElectionAdmin, stores them in a hash-linked
 * chain of blocks, and decrypts all votes using its Tally RSA private key once polls close.
 */
public class VotingBlockchain {

    private final BigInteger adminModulus;
    private final BigInteger adminPublicExponent;

    // key pari used for automatic ballot decryption after polls close
    private final RsaKeys tallyKeys = RsaKeys.generate();

    private final List<Block> chain = new ArrayList<>();
    private final Set<BigInteger> usedCommitments = new HashSet<>();
    private  boolean pollsOpen = true;
    private final List<String> allowedAnswers;

    public VotingBlockchain(BigInteger adminModulus, BigInteger adminPublicExponent, List<String> allowedAnswers){
        validateAnswer(allowedAnswers);

        this.allowedAnswers = List.copyOf(allowedAnswers);
        this.adminModulus = adminModulus;
        this.adminPublicExponent = adminPublicExponent;

    }

    // Ensures the referendum has at least two unique, non-blank answers
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

    public List<String> getAllowedAnswers(){
        return allowedAnswers;
    }

    public BigInteger getTallyModulusN(){
        return tallyKeys.modulusN();
    }

    public BigInteger getTallyPubExponentE(){
        return tallyKeys.publicExponentE();
    }

    public List<Block> getChain(){
        return chain;
    }

    public boolean isPollsOpen(){
        return pollsOpen;
    }

    // Varifies Admin's RSA signature on the commitment and appends the sealed ballot as a new block
    public int submitBallot(BigInteger commitmentX, BigInteger cleanSignature, BigInteger encryptedOpening) throws SecurityException{

        if(!pollsOpen){
            throw new SecurityException("Rejected: polls are closed");
        }

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

        // 2. Verify Admin's RSA signature using Utility
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

    // Closes voting and triggers automatic decryption of all stored ballots
    public void closePollsAndRevealAll(){
        if(!pollsOpen){
            throw new IllegalStateException("Polls are already closed");
        }
        pollsOpen = false;

        for(Block block : chain){
            revealBlock(block);

        }
    }

    // Decrypts a single ballot and verifies that the vote matches its original SHA-256 commitment
    private void revealBlock(Block block) {
        try{
            // 1. Decrypt candidate:salt using Tally Private Key
            String decryptedPayload = VoteCommitment.decryptOpening(
                    block.encryptedOpening, tallyKeys.privateExponentD(), tallyKeys.modulusN()
            );

            String[] parts = decryptedPayload.split(":", 2);
            if(parts.length != 2){
                block.markInvalid("corrupted payload format");
                return;
            }

            String candidate = parts[0];
            String salt = parts[1];

            // 2. Decrypted candidate + salt must match commitmentX
            if(!VoteCommitment.verifyCommitment(block.commitmentX, candidate, salt)){
                block.markInvalid("decrypted vote does not match commitment");
                return;
            }

            if(!allowedAnswers.contains(candidate)){
                block.markInvalid("answer not on the ballot");
                return;
            }

            block.reveal(candidate, salt);


        } catch (RuntimeException e){
            block.markInvalid("could not decrypt or verify ballot");
        }
    }

    // Audits the blockchain by recalculating each block's hash and verifying previousHash links
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

    // Counts all valid revealed votes for each allowed referendum answer
    public Map<String, Integer> countVotes(){
        Map<String, Integer> tally = new LinkedHashMap<>();
        for(String answer : allowedAnswers){
            tally.put(answer, 0);
        }

        for(Block b : chain){
            if(b.revealedCandidate != null){
                tally.merge(b.revealedCandidate, 1, Integer::sum);
            }
        }

        return tally;
    }

    // Returns the total number of ballots marked as invalid during decryption
    public int countInvalidBallots(){
        int invalidCount = 0;
        for(Block b: chain){
            if(b.invalid){
                invalidCount++;
            }
        }

        return invalidCount;
    }

    // Prints the blockchain audit status, all blocks, and the final referendum tally to the console
    public void printResult(){
        System.out.println("\nBlockchain ledger audit (Chain Valid: " + isChainValid() + ")");

       for(Block b: chain){
           System.out.printf("ereferendum.model.Block #%d | PrevHash: %s | BlockHash: %s | Vote: %s%n",
                   b.index,
                   b.previousHash.substring(0, 8),
                   b.currentHash.substring(0, 8),
                   b.formatStatus()
                   );
       }

        System.out.println("\nFinal referendum result");
        if(pollsOpen){
            System.out.println("No votes revealed yet (Polls are still open).");
        }else{

            countVotes().forEach((answer, count) -> {
                        System.out.printf("%s : %d vote(s)\n", answer, count);
                    }
            );
        }
        System.out.println("Invalid ballots: " + countInvalidBallots());
    }

}
