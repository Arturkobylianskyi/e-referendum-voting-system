package ereferendum.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Records that a specific authenticated voter (identified by their Keybloak subject ID)
 * has already received a blind signature for a given referendum, preventing double voting.
 */
@Entity
@Table(
        name = "voter_authorizations",
        uniqueConstraints = @UniqueConstraint(columnNames = {"referendum_id", "voter_id"})
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class VoterAuthorization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "referendum_id", nullable = false)
    private Referendum referendum;

    @Column(name="voter_id", nullable = false)
    private String voterId;

    @Column(nullable = false)
    private LocalDateTime authorizedAt;

    public VoterAuthorization(Referendum referendum, String voterId){
        this.referendum = referendum;
        this.voterId = voterId;
        this.authorizedAt = LocalDateTime.now();
    }
}
