package ereferendum.service;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.RsaKeys;

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

    // database of voters who already got a signature
    private final Set<String> usedVoters = new HashSet<>();


    public BigInteger getModulusN(){
        return keys.modulusN();
    }

    public BigInteger getPubExponentE(){
        return keys.publicExponentE();
    }

    // Verifies that the voterID is present, confirms they haven't voted, and blind-signs their commitment.
    public BigInteger authorizeAndSign(String voterId, BigInteger blindedMsg) throws SecurityException{
        if(voterId == null || voterId.isBlank()){
            throw new SecurityException("Rejected: Voter ID cannot be blank");
        }

        if(usedVoters.contains(voterId)){
            throw new SecurityException("Rejected: Voter " + voterId + " has already received a blind signature!");
        }

        usedVoters.add(voterId);
        return BlindSignatureMath.blindSign(blindedMsg, keys.privateExponentD(), keys.modulusN());
    }


}
