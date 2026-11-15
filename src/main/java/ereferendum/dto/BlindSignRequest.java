package ereferendum.dto;


/**
 * Request payload containing the blinded commitment sent by an authenticated voter
 * @param blindedMessage
 */
public record BlindSignRequest(String blindedMessage) {
}
