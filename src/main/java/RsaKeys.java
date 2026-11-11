import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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

    public BigInteger modulsN(){
        return publicKey.getModulus();
    }

    public BigInteger publicExponentE(){
        return publicKey.getPublicExponent();
    }

    public BigInteger privateExponentD(){
        return privateKey.getPrivateExponent();
    }
}
