import java.math.BigInteger;
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

        RsaKeys keys = RsaKeys.generate();
        this.modulusN = keys.modulsN();
        this.pubExponentE = keys.publicExponentE();
        this.privExponentD = keys.privateExponentD();
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
