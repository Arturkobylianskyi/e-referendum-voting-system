package ereferendum.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Holder for a generated 2048-bit RSA key pair
 * providing direct access to BigInteger modulus and exponents.
 * @param publicKey
 * @param privateKey
 */
public record RsaKeys(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

    private static final int KEY_SIZE = 2048;

    public static RsaKeys generate(){
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            KeyPair pair = generator.generateKeyPair();
            return new RsaKeys((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate());
        }catch (NoSuchAlgorithmException e){
            throw new IllegalStateException("RSA is not available", e);
        }
    }

    public BigInteger modulusN(){
        return publicKey.getModulus();
    }

    public BigInteger publicExponentE(){
        return publicKey.getPublicExponent();
    }

    public BigInteger privateExponentD(){
        return privateKey.getPrivateExponent();
    }
}
