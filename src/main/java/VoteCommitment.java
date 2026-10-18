import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class VoteCommitment {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private VoteCommitment(){};

    public static String generateSalt(){
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);

        return HexFormat.of().formatHex(randomBytes);
    }

    public static BigInteger createCommitment(String vote, String salt){
        if(vote == null || vote.isBlank() || salt == null || salt.isBlank()){
            throw new IllegalArgumentException("vote and salt can't be blank");
        }
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String payload = vote.trim() + ":" + salt.trim();
            byte[] hashByte = digest.digest(payload.getBytes(StandardCharsets.UTF_8));

            return new BigInteger(1, hashByte);
        } catch (NoSuchAlgorithmException e){
            throw new RuntimeException("Algorytm SHA-256 is not available", e);
        }
    }

    public static boolean verifyCommitment(BigInteger originalCommitment, String revealedVote, String revealedSalt){
        BigInteger recomputed = createCommitment(revealedVote, revealedSalt);
        return originalCommitment.equals(recomputed);
    }

//    public static void main(String[] args){
//        String candidate = "Kandydat Nowak";
//
//        // два різні виборці голосують за того самого кандидата
//        String saltVoter1 = generateSalt();
//        String saltVoter2 = generateSalt();
//
//        BigInteger commit1 = createCommitment(candidate, saltVoter1);
//        BigInteger commit2 = createCommitment(candidate, saltVoter2);
//
//        System.out.println("Candidate 1 salt r1 : " + saltVoter1);
//        System.out.println("Candidate 1 commitment (x1, hex): " + commit1.toString(16));
//        System.out.println("Candidate 2 commitment (x2, hex): " + commit2.toString(16));
//        System.out.println("are the commitments the same for the same vote ?" + commit1.equals(commit2));
//
//        // test reveal honest
//        boolean validOpen = verifyCommitment(commit1, "Kandydat Nowak", saltVoter1);
//        System.out.println("\n checking of revealing (kandydat Nowa + r1): " + validOpen);
//
//        // test 2
//        boolean cheatVote = verifyCommitment(commit1, "Kandydat Kowalski", saltVoter1);
//        System.out.println("attempt of change the choice while reaveal (Kandydat Kowalski + r1)" + cheatVote);
//
//        // test 3 test to send other salt
//        boolean cheatSalt = verifyCommitment(commit1, "Kandydat Nowak", saltVoter2);
//        System.out.println("attempt of pass other salt (Kandydat Nowak + r2)"+ cheatSalt);
//
//    }
}
