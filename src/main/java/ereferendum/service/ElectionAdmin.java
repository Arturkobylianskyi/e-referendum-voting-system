package ereferendum;

import java.math.BigInteger;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

/**
 * Registration authority responsible for verifying voter eligibility
 * and issuing RSA blind signatures on blinded vote commitments
 */
public class ElectionAdmin {

    private final RsaKeys keys = RsaKeys.generate();
    private final LocalDate electionDate;
    private final Set<String> usedPesel = new HashSet<>(); // database of voters who already got a signature

    public ElectionAdmin(LocalDate electionDate){
        this.electionDate = electionDate;
    }

    public BigInteger getModulusN(){
        return keys.modulusN();
    }

    public BigInteger getPubExponentE(){
        return keys.publicExponentE();
    }

    // Verifies that the voter is an adult, confirms they haven't voted, and blind-signs their commitment.
    public BigInteger authorizeAndSign(String pesel, BigInteger blindedMsg) throws SecurityException{
        // 1. Validate PESEL checksum and age
        if(!PeselValidator.isAdultVoter(pesel, electionDate)){
            throw new SecurityException("Rejected: Invalid PESEL or voter is under 18 (" + pesel + ")");
        }

        // 2. prevent double voting
        if(usedPesel.contains(pesel)){
            throw new SecurityException("Rejected: PESEL " + pesel + " has already received a blind signature!");
        }

        // 3. Record PESEL and sign the blinded message
        usedPesel.add(pesel);
        return BlindSignatureMath.blindSign(blindedMsg, keys.privateExponentD(), keys.modulusN());
    }


}
