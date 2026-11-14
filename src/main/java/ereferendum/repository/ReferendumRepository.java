package ereferendum.repository;

import ereferendum.model.Referendum;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository managing Referendum entities in PostgreSQL
 */
public interface ReferendumRepository extends JpaRepository<Referendum, Long> {
}
