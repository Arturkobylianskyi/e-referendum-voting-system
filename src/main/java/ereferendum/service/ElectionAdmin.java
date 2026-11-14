package ereferendum.service;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.RsaKeys;
import ereferendum.model.Referendum;
import ereferendum.model.VoterAuthorization;
import ereferendum.repository.ReferendumRepository;
import ereferendum.repository.VoteAuthorizationRepository;
import org.springframework.stereotype.Service;

import java.math.BigInteger;


/**
 * Registration authority responsible for verifying voter eligibility
 * and issuing RSA blind signatures on blinded vote commitments
 */
@Service
public class ElectionAdmin {

    private final RsaKeys keys = RsaKeys.generate();
    private final ReferendumRepository referendumRepository;
    private final VoteAuthorizationRepository authRepository;

    public ElectionAdmin(ReferendumRepository referendumRepository, VoteAuthorizationRepository authRepository){
        this.referendumRepository = referendumRepository;
        this.authRepository = authRepository;
    }

    public BigInteger getModulusN(){
        return keys.modulusN();
    }

    public BigInteger getPubExponentE(){
        return keys.publicExponentE();
    }

    // Verifies that the voterID is present, confirms they haven't voted, and blind-signs their commitment.
    public BigInteger authorizeAndSign(Long referendumId, String voterId, BigInteger blindedMsg) throws SecurityException{
        if(voterId == null || voterId.isBlank()){
            throw new SecurityException("Rejected: Voter ID cannot be blank");
        }

        Referendum referendum = referendumRepository.findById(referendumId)
                .orElseThrow(() -> new IllegalArgumentException("Referendum not found: " + referendumId));

        if(!referendum.isPollsOpen()){
            throw new SecurityException("Rejected: polls are closed");
        }

        if(authRepository.existsByReferendumIdAndVoterId(referendumId, voterId)){
            throw new SecurityException("Rejected: Voter " + voterId + " has already received a blind signature!");
        }

        authRepository.save(new VoterAuthorization(referendum, voterId));
        return BlindSignatureMath.blindSign(blindedMsg, keys.privateExponentD(), keys.modulusN());
    }


}
