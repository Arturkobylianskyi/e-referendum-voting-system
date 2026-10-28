import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

public class ElectionAdmin {

    private final BigInteger modulusN; // public key part N
    private final BigInteger pubExponentE; // public key part e
    private final BigInteger privExponentD; // secrect key d (know only to admin)

    private final LocalDate electionDate;
    private final Set<String> usedPesel = new HashSet<>(); // database of voters who already got a signature

    public ElectionAdmin(LocalDate electionDate){
        this.electionDate = electionDate;

        try{
            // Generate 2048-bit RSA key pair on startup
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();

            this.modulusN = pub.getModulus();
            this.pubExponentE = pub.getPublicExponent();
            this.privExponentD = priv.getPrivateExponent();

        } catch(Exception e){
            throw new RuntimeException("Failed to initialize Admin RSA keys", e);
        }
    }

    public BigInteger getModulusN(){
        return modulusN;
    }

    public BigInteger getPubExponentE(){
        return pubExponentE;
    }

    // Verifies voter eligibility via PESEL and signs the blinded commitment
    public BigInteger authorizeAndSign(String pesel, BigInteger blindedMsg) throws SecurityException{
        // 1. Validate PESEL checksum and age using Utility
        if(!PeselValidator.isAdultVoter(pesel, electionDate)){
            throw new SecurityException("Rejected: Invalid PESEL or voter is under 18 (" + pesel + ")");
        }

        // 2. prevent double voting
        if(usedPesel.contains(pesel)){
            throw new SecurityException("Rejected: PESEL " + pesel + " has already received a blind signature!");
        }

        // 3. Record PESEL and sign the blinded message using Utility
        usedPesel.add(pesel);
        return BlindSignatureMath.blindSign(blindedMsg, privExponentD, modulusN);
    }


}
