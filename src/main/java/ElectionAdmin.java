import java.math.BigInteger;
import java.security.Key;
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
    public BigInteger authorizeAndSign(String pesel, BigInteger blindedMsg){
        // 1. Validate PESEL checksum and 18+ age using Utility
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

    public static void main(String[] args){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());

        String validAdultPesel = "99051512343";
        String minorPesel = "15251012349";
        String errPesel = "12345678909";

        // Simulate a voter preparing a blinded message using Utilities
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment("Kandydat Nowak", salt);
        BigInteger b = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(commitmentX, b, admin.getPubExponentE(), admin.getModulusN());

        // test 1: Valid adult voter requests signature -> success
        BigInteger blindSig = admin.authorizeAndSign(validAdultPesel, blindedMsg);
        BigInteger cleanSig = BlindSignatureMath.ublind(blindSig, b, admin.getModulusN());
        boolean isVerified = BlindSignatureMath.verifySignature(commitmentX, cleanSig, admin.getPubExponentE(), admin.getModulusN());
        System.out.println("Test 1 (Valid adult): Signature verified = " + isVerified);

        // test 2: Same voter tries to get a second signature -> Blocked
        try {
            admin.authorizeAndSign(validAdultPesel, blindedMsg);
        } catch (SecurityException ex){
            System.out.println("Test 2 (Double voting): " + ex.getMessage());
        }

        // test 3 Underage voter tries to get a signature -> Blocked
        try {
            admin.authorizeAndSign(minorPesel, blindedMsg);
        }catch (SecurityException ex){
            System.out.println("Test 3 (Underage voter): " + ex.getMessage());
        }



    }

}
