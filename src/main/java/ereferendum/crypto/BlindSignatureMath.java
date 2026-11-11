package ereferendum.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Mathematical operations for RSA blind signature scheme
 * blinding factor generation, message blinding, blind signing, unblinding and verification
 */
public class BlindSignatureMath {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private BlindSignatureMath(){};

    // generates a random blinding factor 'b' such that 1 < b < N and gcd(b, N) == 1
    public static BigInteger generateBlindFactor(BigInteger modulusN){
        while(true){
            BigInteger b = new BigInteger(modulusN.bitLength() -1, SECURE_RANDOM);
            if(b.compareTo(BigInteger.ONE) > 0 && b.gcd(modulusN).equals(BigInteger.ONE)){
                return b;
            }
        }
    }

    // Voter: Blinds the vote commitment using the Administrator's public key (e, N): (x * (b ^ e)) mod N
    public static BigInteger blind(BigInteger commitmentX, BigInteger blindingFactorB, BigInteger pubExponentE, BigInteger modulusN){
        BigInteger mask = blindingFactorB.modPow(pubExponentE, modulusN);
        return commitmentX.multiply(mask).mod(modulusN);
    }

    //Administrator: Sign the blinded message using the private exponent 'd': (blindedMsg ^ d) mod N
    public static BigInteger blindSign(BigInteger blindedMsg, BigInteger privExponentD, BigInteger modulusN){
        return blindedMsg.modPow(privExponentD, modulusN);
    }

    // Voter: Removes the blinding factor 'b' to obtain a valid RSA signature on 'commitmentX' : (blindSig * b^-1) mod N
    public static BigInteger unblind(BigInteger blindSig, BigInteger blindingFactorB, BigInteger modulusN){
        BigInteger bInverse = blindingFactorB.modInverse(modulusN);
        return blindSig.multiply(bInverse).mod(modulusN);
    }

    // Blockchain: Verifies that the unblinded RSA signature matches the commitment
    public static boolean verifySignature(BigInteger commitmentX, BigInteger cleanSignature, BigInteger pubExponentE, BigInteger modulusN){
        BigInteger recoveredX = cleanSignature.modPow(pubExponentE, modulusN);
        return recoveredX.equals(commitmentX);
    }

}
