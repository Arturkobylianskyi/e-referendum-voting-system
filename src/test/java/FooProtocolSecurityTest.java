import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.*;

public class FooProtocolSecurityTest {

    // helper valid pesel generator
    private static String generateValidPesel(String first10Digits){
        int[] weight = {1, 3, 7, 9, 1, 3, 7, 9, 1, 3};
        int sum = 0;
        for(int i = 0; i < 10; i++){
            sum += Character.getNumericValue(first10Digits.charAt(i)) * weight[i];
        }

        int controlDigit = (10 - (sum % 10)) % 10;
        return first10Digits + controlDigit;
    }

    @Test
    void shouldValidatePeselAndBlockUnderageVoter(){
        LocalDate electionDay = LocalDate.of(2026, 10, 24);
        ElectionAdmin admin = new ElectionAdmin(electionDay);

        String underagePesel = generateValidPesel("1225101234");// Born 10.05.2012
        String fakeChecksumPesel = "99051512340";

        // Check that validator rejects both
        assertFalse(PeselValidator.isAdultVoter(underagePesel, electionDay));
        assertFalse(PeselValidator.isValidChecksum(fakeChecksumPesel));

        // Check that Admin throws SecurityException when underage person tries to vote
        assertThrows(SecurityException.class, () -> {
            admin.authorizeAndSign(underagePesel, BigInteger.valueOf(12345));
        });
    }

    @Test
    void shouldBlockDoubleVotingWithSamePesel(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        String validAdultPesel = generateValidPesel("9905151234"); // Born 15.05.1999

        // 1st time: Voter gets blind signature seccessfully
        BigInteger firstSignature = admin.authorizeAndSign(validAdultPesel, BigInteger.valueOf(77777));
        assertNotNull(firstSignature);

        // 2nd time: Same Pesel tries to get another signature
        assertThrows(SecurityException.class, () -> admin.authorizeAndSign(validAdultPesel, BigInteger.valueOf(888888)));
    }


    @Test
    void shouldRejectBallotWithForgedAdminSignature(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE());

        // Hacker creates a valid commitment, but invents a fake RSA signature without going to Admin
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment("Kandydat Nowak", salt);
        BigInteger forgetSignature = BigInteger.valueOf(999999999);
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "Kandydat Nowak", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        // Blockchain must reject the ballot because RSA signature varification fails
        assertThrows(SecurityException.class, () -> {
            blockchain.submitBallot(commitmentX, forgetSignature, encryptedOpening);
        });
    }


    @Test
    void shouldDetectMismatchedCommitmentAndEncryptedOpeningDuringAutoReveal() {
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE());

        String pesel = generateValidPesel("9511205432");
        String salt = VoteCommitment.generateSalt();

        BigInteger commitmentX = VoteCommitment.createCommitment("Kandydat_Nowak", salt);
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(commitmentX, maskB, admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig = admin.authorizeAndSign(pesel, blindedMsg);
        BigInteger cleanSig = BlindSignatureMath.unblind(blindSig, maskB, admin.getModulusN());

        BigInteger dishonestEncryptedOpening = VoteCommitment.encryptOpening(
                "Kandydat_Kowalski", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );
        blockchain.submitBallot(commitmentX, cleanSig, dishonestEncryptedOpening);

        assertThrows(SecurityException.class, () -> {
            blockchain.closePollsAndRevealAll();
        });
    }


    @Test
    void shouldSuccessfullyCompleteSingleClickVotingAndAutoReveal(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE());

        String pesel = generateValidPesel("0122149876");
        String candidate = "Kandydat Nowak";
        String salt = VoteCommitment.generateSalt();

        // phase 1
        BigInteger commitmentX = VoteCommitment.createCommitment(candidate, salt);
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(commitmentX, maskB, admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig = admin.authorizeAndSign(pesel, blindedMsg);
        BigInteger cleanSig = BlindSignatureMath.unblind(blindSig, maskB, admin.getModulusN());

        // phase 2
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "Kandydat Nowak", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );
        int blockIndex = blockchain.submitBallot(commitmentX, cleanSig, encryptedOpening);

        // phase 3
        blockchain.closePollsAndRevealAll();

        assertEquals(candidate, blockchain.getChain().get(blockIndex).revealedCandidate);
        assertTrue(blockchain.isChainValid());
    }

}





















