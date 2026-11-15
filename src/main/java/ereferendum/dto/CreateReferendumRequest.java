package ereferendum.dto;

import java.util.List;

/**
 * Request payload sent by an Admin to create a new referendum
 * @param title
 * @param question
 * @param allowedAnswers
 */
public record CreateReferendumRequest(
        String title,
        String question,
        List<String> allowedAnswers
) {
}
