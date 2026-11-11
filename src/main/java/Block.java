import java.math.BigInteger;

public class Block{
    public final int index;
    public final BigInteger commitmentX;
    public final BigInteger cleanSignature;
    public final BigInteger encryptedOpening;
    public final String previousHash;
    public final String currentHash;

    // filled later during Phase 3 (Reveal)
    public String revealedCandidate = null;
    public String revealedSalt = null;

    public boolean invalid = false;
    public String invalidReason = null;

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

    public void reveal(String candidate, String salt){
        this.revealedCandidate = candidate;
        this.revealedSalt = salt;
    }

    public void markInvalid(String reason){
        this.invalid = true;
        this.invalidReason = reason;
    }

    public String formatStatus(){
        if(revealedCandidate != null){
            return revealedCandidate;
        }

        if(invalid){
            return String.format("[INVALID: %s]", invalidReason);
        }

        return "[SEALED]";
    }


}