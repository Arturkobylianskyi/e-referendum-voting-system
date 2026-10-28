import java.math.BigInteger;
import java.security.SecureRandom;


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
    public static BigInteger unblind(BigInteger blindSig, BigInteger blindingFactorB, BigInteger modulsN){
        BigInteger bInverse = blindingFactorB.modInverse(modulsN);
        return blindSig.multiply(bInverse).mod(modulsN);
    }

    public static boolean verifySignature(BigInteger commitmentX, BigInteger cleanSignature, BigInteger pubExponentE, BigInteger modulsN){
        BigInteger recoveredX = cleanSignature.modPow(pubExponentE, modulsN);
        return recoveredX.equals(commitmentX);
    }

}
