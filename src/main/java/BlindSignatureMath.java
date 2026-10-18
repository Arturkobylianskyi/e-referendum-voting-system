import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class BlindSignatureMath {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private BlindSignatureMath(){};

    // generates a random blinding factor 'b' such that 1 < b < N and gcd(b, N) == 1
    public static BigInteger generateBlindFactor(BigInteger modulusN){
        BigInteger b;
        do{
            b = new BigInteger(modulusN.bitLength() - 1, SECURE_RANDOM);
        } while (b.compareTo(BigInteger.ONE) <= 0 || ! b.gcd(modulusN).equals(BigInteger.ONE));

        return b;
    }

    // Voter: Blinds the vote commitment using the Administrator's public key (e, N)
    // Formula: blindedMsg = (x * (b ^ e)) mod N
    public static BigInteger blind(BigInteger commitmentX, BigInteger blindingFactorB, BigInteger pubExponentE, BigInteger modulsN){
        BigInteger mask = blindingFactorB.modPow(pubExponentE, modulsN);
        return commitmentX.multiply(mask).mod(modulsN);
    }

    //Administrator: Sign the blinded message using the private exponent 'd'
    //Formula: blindSig = (blindedMsg ^ d) mod N
    public static BigInteger blindSign(BigInteger blindedMsg, BigInteger privExponentD, BigInteger modulsN){
        return blindedMsg.modPow(privExponentD, modulsN);
    }

    // Voter: Removes the blinding factor 'b' to obtain a valid RSA signature on 'commitmentX'
    // Formula: cleanSignature = (blindSig * b^-1) mod N
    public static BigInteger ublind(BigInteger blindSig, BigInteger blindingFactorB, BigInteger modulsN){
        BigInteger bInverse = blindingFactorB.modInverse(modulsN);
        return blindSig.multiply(bInverse).mod(modulsN);
    }

    public static boolean verifySignature(BigInteger commitmentX, BigInteger cleanSignature, BigInteger pubExponentE, BigInteger modulsN){
        BigInteger recoveredX = cleanSignature.modPow(pubExponentE, modulsN);
        return recoveredX.equals(commitmentX);
    }

//    public static void main(String[] args) throws Exception{
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(2048);
//
//        var keyPair = keyGen.generateKeyPair();
//        var pubKey = (RSAPublicKey) keyPair.getPublic();
//        var privKey = (RSAPrivateKey) keyPair.getPrivate();
//
//        BigInteger N = pubKey.getModulus();
//        BigInteger e = pubKey.getPublicExponent();
//        BigInteger d = privKey.getPrivateExponent();
//
//        // 1.  Voter creates salted commitment
//        String salt = VoteCommitment.generateSalt();
//        BigInteger originalCommitmentX = VoteCommitment.createCommitment("Kandydat Nowak", salt);
//        System.out.println("1. Original commitment (x):    " + originalCommitmentX);
//
//        // 2. Voret blinds the commitment before sending to Admin
//        BigInteger b = generateBlindFactor(N);
//        BigInteger blindedMsg = blind(originalCommitmentX, b, e, N);
//        System.out.println("2. Blinded msg (seen by Admin):    " + blindedMsg.toString(16).substring(0, 24) + "....");
//
//
//        // 3. Admin signs the blinded message
//        BigInteger blindSig = blindSign(blindedMsg, d, N);
//
//        // 4. Voter ublinds the signature
//        BigInteger cleanSignature = ublind(blindSig, b, N);
//        System.out.println("3. Ublinded RSA signature:     " + cleanSignature.toString(16).substring(0, 24) + "....");
//
//        // 5. Blockchain verifies signature against original commitment
//        boolean isValid = verifySignature(originalCommitmentX, cleanSignature, e, N);
//        System.out.println("\nSignature verification on-chain (expectd true): " + isValid);
//
//        // 6. Tamper test: trying to use the valid signature with a different candidate commitment
//        BigInteger fakeCommitmentX = VoteCommitment.createCommitment("Kandydat Kowalski", salt);
//        boolean isFakeValid = verifySignature(fakeCommitmentX, cleanSignature, e, N);
//        System.out.println("Signature verification for tapered vote (expected false):   " + isFakeValid);
//
//    }

//    [1. originalCommitmentX]  (Солений хеш голосу: SHA-256("Nowak:salt"))
//            │
//            ▼  викликаємо: blind(originalCommitmentX, b, e, N)
//    [2. blindedMsg]           (Хеш у масці 'b' — його бачить Адмін)
//            │
//            ▼  викликаємо: blindSign(blindedMsg, d, N)
//    [3. blindSig]             (Підпис Адміна, але все ще поверх маски 'b')
//            │
//            ▼  викликаємо: unblind(blindSig, b, N)
//    [4. cleanSignature]       (Маску 'b' зняли! Залишився чистий підпис під originalCommitmentX)
//            │
//            ▼  викликаємо: verifySignature(originalCommitmentX, cleanSignature, e, N)
//    [5. true / false]         (Блокчейн звіряє #1 і #4 -> повертає true!)
}
