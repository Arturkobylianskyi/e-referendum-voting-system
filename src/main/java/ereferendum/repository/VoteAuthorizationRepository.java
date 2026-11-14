package ereferendum.repository;

import ereferendum.model.VoterAuthorization;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for checking and recording voter blind-signature authorizations
 */
public interface VoteAuthorizationRepository extends JpaRepository<VoterAuthorization, Long> {
    boolean existsByReferendumIdAndVoterId(Long referendumId, String voterId);
}

