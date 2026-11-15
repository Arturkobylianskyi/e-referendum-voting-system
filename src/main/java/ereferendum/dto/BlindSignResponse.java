package ereferendum.dto;

/**
 * Response payload returning the RSA blind signature issued by the ElectionAdmin
 * @param blindSignature
 */
public record BlindSignResponse(String blindSignature) {
}
