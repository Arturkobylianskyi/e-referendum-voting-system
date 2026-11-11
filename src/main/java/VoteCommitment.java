import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HexFormat;

/**
 * Cryptographic utility for creating and verifying salted SHA-256 vote commitments,
 * as well as RSA encryption and decryption of the commitment opening payload
 */
public class VoteCommitment {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private VoteCommitment(){};

    public static String generateSalt(){
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);

        return HexFormat.of().formatHex(randomBytes);
    }

    // Computes a SHA-256 commitment hash from the given vote and random salt
    public static BigInteger createCommitment(String vote, String salt){
        String payload = formatPayload(vote, salt);
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashByte = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, hashByte);
        } catch (Exception e){
            throw new RuntimeException("SHA-256 algorithm is not available", e);
        }
    }

    // Verifies whether the revealed vote and salt match the original SHA-256 commitment
    public static boolean verifyCommitment(BigInteger originalCommitment, String revealedVote, String revealedSalt){
        BigInteger recomputed = createCommitment(revealedVote, revealedSalt);
        return originalCommitment.equals(recomputed);
    }

    // Encrypts the opening payload "vote:salt" with the Tally RSA public key: C = M^e mod N
    public static BigInteger encryptOpening(String vote, String salt, BigInteger tallyE, BigInteger tallyN) {
        String payload = formatPayload(vote, salt);
        BigInteger messageM = new BigInteger(1, payload.getBytes(StandardCharsets.UTF_8));
        return messageM.modPow(tallyE, tallyN);
    }

    // Decrypts the BigInteger back into "vote:salt": M = C^d mod N
    public static String decryptOpening(BigInteger encryptedOpening, BigInteger tallyD, BigInteger tallyN){
        BigInteger messageM = encryptedOpening.modPow(tallyD, tallyN);
        return new String(messageM.toByteArray(), StandardCharsets.UTF_8);
    }


    private static String formatPayload(String vote, String salt) {
        if(vote == null || vote.isBlank() || salt == null || salt.isBlank()){
            throw new IllegalArgumentException("vote and salt can't be blank");
        }

        return vote.trim() + ":" + salt.trim();
    }







}
