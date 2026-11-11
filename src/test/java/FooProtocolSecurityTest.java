import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class FooProtocolSecurityTest {

    private static final List<String> ANSWERS = List.of("TAK", "NIE");

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

    // helper: full voting flow for one voter, returns index of the block with the ballot
    private static int castVote(ElectionAdmin admin, VotingBlockchain blockchain, String pesel,
                                String committedCandidate, String encryptedCandidate){
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment(committedCandidate, salt);
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(commitmentX, maskB, admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig = admin.authorizeAndSign(pesel, blindedMsg);
        BigInteger cleanSig = BlindSignatureMath.unblind(blindSig, maskB, admin.getModulusN());
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                encryptedCandidate, salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        return blockchain.submitBallot(commitmentX, cleanSig, encryptedOpening);
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
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        // Hacker creates a valid commitment, but invents a fake RSA signature without going to Admin
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment("TAK", salt);
        BigInteger forgetSignature = BigInteger.valueOf(999999999);
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        // Blockchain must reject the ballot because RSA signature varification fails
        assertThrows(SecurityException.class, () -> {
            blockchain.submitBallot(commitmentX, forgetSignature, encryptedOpening);
        });
    }


    @Test
    void shouldMarkMismatchedBallotAsInvalid(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        //dishonest voter: commits to Nowak, but encrypts Kowalski
        int idx = castVote(admin, blockchain, generateValidPesel("9511205432"),
                "TAK", "NIE");

        assertDoesNotThrow(blockchain::closePollsAndRevealAll);

        Block block = blockchain.getChain().get(idx);
        assertTrue(block.invalid);
        assertNull(block.revealedCandidate);
    }

    @Test
    void oneInvalidBallotShouldNotBlockCountingOfOthers(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        int badIdx = castVote(admin, blockchain, generateValidPesel("9511205432"),
                "TAK", "NIE");

        int goodidx = castVote(admin, blockchain, generateValidPesel("9905151234"),
                "TAK", "TAK");

        blockchain.closePollsAndRevealAll();

        assertTrue(blockchain.getChain().get(badIdx).invalid);
        assertEquals("TAK", blockchain.getChain().get(goodidx).revealedCandidate);
        assertTrue(blockchain.isChainValid());
    }


    @Test
    void shouldSuccessfullyCompleteSingleClickVotingAndAutoReveal(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        String pesel = generateValidPesel("0122149876");
        String candidate = "TAK";
        String salt = VoteCommitment.generateSalt();

        // phase 1
        BigInteger commitmentX = VoteCommitment.createCommitment(candidate, salt);
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(commitmentX, maskB, admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig = admin.authorizeAndSign(pesel, blindedMsg);
        BigInteger cleanSig = BlindSignatureMath.unblind(blindSig, maskB, admin.getModulusN());

        // phase 2
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );
        int blockIndex = blockchain.submitBallot(commitmentX, cleanSig, encryptedOpening);

        // phase 3
        blockchain.closePollsAndRevealAll();

        assertEquals(candidate, blockchain.getChain().get(blockIndex).revealedCandidate);
        assertTrue(blockchain.isChainValid());
    }

    @Test
    void shouldRejectBallotForgedWithoutAdmin(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        // Attacker picks any "signature" and computes matching x himself
        BigInteger fakeSignature = new BigInteger("123456789");
        BigInteger fakeCommitment = fakeSignature.modPow(admin.getPubExponentE(), admin.getModulusN());

        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", VoteCommitment.generateSalt(),
                blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(fakeCommitment, fakeSignature, encryptedOpening));
    }

    @Test
    void shouldRejectTrivialSignatureOne(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", VoteCommitment.generateSalt(),
                blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(BigInteger.ONE, BigInteger.ONE, encryptedOpening));
    }

    @Test
    void shouldKeepBallotsSealedWhilePollsOpen(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        int idx = castVote(admin, blockchain, generateValidPesel("9905151234"),
                "TAK", "TAK");

        // before closing nobody knows the vote
        assertTrue(blockchain.isPollsOpen());
        assertNull(blockchain.getChain().get(idx).revealedCandidate);
    }

    @Test
    void shouldRejectBallotAfterPollsClosed(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        castVote(admin, blockchain, generateValidPesel("9905151234"),
                "TAK", "TAK");
        blockchain.closePollsAndRevealAll();

        assertThrows(SecurityException.class, () -> {
            castVote(admin, blockchain, generateValidPesel("9511205432"),
                    "NIE", "NIE");
        });

        assertEquals(1, blockchain.getChain().size());
    }

    @Test
    void shouldNotAllowClosingPollsTwice(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        blockchain.closePollsAndRevealAll();

        assertFalse(blockchain.isPollsOpen());
        assertThrows(IllegalStateException.class, blockchain::closePollsAndRevealAll);
    }

    @Test
    void shouldMarkAnswerOutsideBallotAsInvalid() {
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);

        int idx = castVote(admin, blockchain, generateValidPesel("9905151234"), "MOZE", "MOZE");

        blockchain.closePollsAndRevealAll();

        assertTrue(blockchain.getChain().get(idx).invalid);
        assertNull(blockchain.getChain().get(idx).revealedCandidate);
    }

    @Test
    void shouldRejectInvalidAnswerList(){
        ElectionAdmin admin = new ElectionAdmin(LocalDate.now());
        BigInteger n = admin.getModulusN();
        BigInteger e = admin.getPubExponentE();

        assertThrows(IllegalArgumentException.class, () -> new VotingBlockchain(n, e, List.of("TAK")));
        assertThrows(IllegalArgumentException.class, () -> new VotingBlockchain(n, e, List.of("TAK", "TAK")));
        assertThrows(IllegalArgumentException.class, () -> new VotingBlockchain(n, e, List.of("TAK", "N:IE")));
        assertThrows(IllegalArgumentException.class, () -> new VotingBlockchain(n, e, List.of("TAK", " ")));
    }

}





















