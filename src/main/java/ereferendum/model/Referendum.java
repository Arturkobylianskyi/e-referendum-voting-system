package ereferendum.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a single referendum stored in PostgreSQL with its title,
 * question, allowed answers, and open/closed status
 */
@Entity
@Table(name="referendum")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Referendum {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String question;

    @Column(nullable = false)
    private boolean pollsOpen = true;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "referendum_answers", joinColumns = @JoinColumn(name="referendum_id"))
    @Column(name="answer", nullable = false)
    private List<String> allowedAnswers;

    public Referendum(String title, String question, List<String> allowedAnswers){
        this.title = title;
        this.question = question;
        this.allowedAnswers = new ArrayList<>(allowedAnswers);
    }

    public void closePolls(){
        this.pollsOpen = false;
    }

}


































