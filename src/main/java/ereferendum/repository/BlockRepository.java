package ereferendum.repository;

import ereferendum.model.Block;
import org.springframework.data.jpa.repository.JpaRepository;

import java.math.BigInteger;
import java.util.List;

public interface BlockRepository extends JpaRepository<Block, Long> {
    // Return all blocks for a specific referendum ordered by their chain index
    List<Block> findByReferendumIdOrderByIndexAsc(Long referendumId);

    // Checks if a ballot commitment has already been submitted to this referendum's chain
    boolean existsByReferendumIdAndCommitmentX(Long referendumId, BigInteger commitmentX);

}
