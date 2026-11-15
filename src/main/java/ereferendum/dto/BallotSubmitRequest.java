package ereferendum.dto;

/**
 * Anonymous ballot payload submitted to the public blockchain containing the SHA256
 * vote commitment, unblinded Admin RSA signature, and Tally-encrypted vote opening.
 * @param commitmentX
 * @param cleanSignature
 * @param encryptedOpening
 */
public record BallotSubmitRequest(
        String commitmentX,
        String cleanSignature,
        String encryptedOpening
) {
}
