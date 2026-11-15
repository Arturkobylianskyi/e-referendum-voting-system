package ereferendum.dto;

import java.util.List;
import java.util.Map;

/**
 * Complete public state of a referendum including its metadata, RSA public keys,
 * blockchain integrity status, tally results, and block ledger
 * @param id
 * @param title
 * @param question
 * @param pollsOpen
 * @param allowedAnswers
 * @param adminModulusN
 * @param adminPublicExponentE
 * @param tallyModulusN
 * @param tallyPublicExponentE
 * @param chainValid
 * @param results
 * @param invalidBallots
 * @param blocks
 */
public record ReferendumDetailsResponse(
        Long id,
        String title,
        String question,
        boolean pollsOpen,
        List<String> allowedAnswers,
        String adminModulusN,
        String adminPublicExponentE,
        String tallyModulusN,
        String tallyPublicExponentE,
        boolean chainValid,
        Map<String, Integer> results,
        int invalidBallots,
        List<BlockDto> blocks
) {
}
