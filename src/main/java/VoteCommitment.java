import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HexFormat;

public class VoteCommitment {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private VoteCommitment(){};

    public static String generateSalt(){
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);

        return HexFormat.of().formatHex(randomBytes);
    }

    public static BigInteger createCommitment(String vote, String salt) throws RuntimeException{
        if(vote == null || vote.isBlank() || salt == null || salt.isBlank()){
            throw new IllegalArgumentException("vote and salt can't be blank");
        }
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String payload = vote.trim() + ":" + salt.trim();
            byte[] hashByte = digest.digest(payload.getBytes(StandardCharsets.UTF_8));

            return new BigInteger(1, hashByte);
        } catch (Exception e){
            throw new RuntimeException("Algorytm SHA-256 is not available", e);
        }
    }

    public static boolean verifyCommitment(BigInteger originalCommitment, String revealedVote, String revealedSalt){
        BigInteger recomputed = createCommitment(revealedVote, revealedSalt);
        return originalCommitment.equals(recomputed);
    }

    // Encrypts "candidate:salt" directly as a BigInteger: C = M^e mod N
    public static BigInteger encryptOpening(String candidate, String salt, BigInteger tallyE, BigInteger tallyN) {
        String payload = candidate + ":" + salt;
        BigInteger messageM = new BigInteger(1, payload.getBytes(StandardCharsets.UTF_8));
        return messageM.modPow(tallyE, tallyN);
    }

    // Decrypts the BigInteger back into "candidate:salt": M = C^d mod N
    public static String decryptOpening(BigInteger encryptedOpening, BigInteger tallyD, BigInteger tallyN){
        BigInteger messageM = encryptedOpening.modPow(tallyD, tallyN);
        return new String(messageM.toByteArray(), StandardCharsets.UTF_8);
    }

}
