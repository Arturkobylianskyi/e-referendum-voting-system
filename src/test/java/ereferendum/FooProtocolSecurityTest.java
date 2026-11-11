package ereferendum;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.VoteCommitment;
import ereferendum.model.Block;
import ereferendum.service.ElectionAdmin;
import ereferendum.service.PeselValidator;
import ereferendum.service.VotingBlockchain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class FooProtocolSecurityTest {

    private static final List<String> ANSWERS = List.of("TAK", "NIE");
    private ElectionAdmin admin;
    private VotingBlockchain blockchain;

    @BeforeEach
    void setUp(){
        admin = new ElectionAdmin(LocalDate.now());
        blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), ANSWERS);
    }


    // helper valid pesel generator
    private static String generateValidPesel(String first10Digits){
        return PeselValidator.generateValidPesel(first10Digits);
    }

    private BigInteger signCommitment(String pesel, BigInteger commitmentX){
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(commitmentX, maskB,
                admin.getPubExponentE(), admin.getModulusN());
        BigInteger blindSig = admin.authorizeAndSign(pesel, blindedMsg);

        return BlindSignatureMath.unblind(blindSig, maskB, admin.getModulusN());
    }

    // helper: full voting flow for one voter, returns index of the block with the ballot
    private int castVote(String pesel, String committedCandidate, String encryptedCandidate){
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment(committedCandidate, salt);
        BigInteger cleanSig = signCommitment(pesel, commitmentX);
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
        
        int idx = castVote( generateValidPesel("9511205432"),
                "TAK", "NIE");

        assertDoesNotThrow(blockchain::closePollsAndRevealAll);

        Block block = blockchain.getChain().get(idx);
        assertTrue(block.invalid);
        assertNull(block.revealedCandidate);
    }

    @Test
    void oneInvalidBallotShouldNotBlockCountingOfOthers(){
       

        int badIdx = castVote( generateValidPesel("9511205432"),
                "TAK", "NIE");

        int goodidx = castVote( generateValidPesel("9905151234"),
                "TAK", "TAK");

        blockchain.closePollsAndRevealAll();

        assertTrue(blockchain.getChain().get(badIdx).invalid);
        assertEquals("TAK", blockchain.getChain().get(goodidx).revealedCandidate);
        assertTrue(blockchain.isChainValid());
    }


    @Test
    void shouldSuccessfullyCompleteSingleClickVotingAndAutoReveal(){

        String pesel = generateValidPesel("0122149876");
        int blockIndex = castVote(pesel, "TAK", "TAK");

        blockchain.closePollsAndRevealAll();

        assertEquals("TAK", blockchain.getChain().get(blockIndex).revealedCandidate);
        assertTrue(blockchain.isChainValid());
    }

    @Test
    void shouldRejectBallotForgedWithoutAdmin(){
       

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
       

        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", VoteCommitment.generateSalt(),
                blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(BigInteger.ONE, BigInteger.ONE, encryptedOpening));
    }

    @Test
    void shouldKeepBallotsSealedWhilePollsOpen(){
       

        int idx = castVote( generateValidPesel("9905151234"),
                "TAK", "TAK");

        // before closing nobody knows the vote
        assertTrue(blockchain.isPollsOpen());
        assertNull(blockchain.getChain().get(idx).revealedCandidate);
    }

    @Test
    void shouldRejectBallotAfterPollsClosed(){
       

        castVote( generateValidPesel("9905151234"),
                "TAK", "TAK");
        blockchain.closePollsAndRevealAll();

        assertThrows(SecurityException.class, () -> {
            castVote( generateValidPesel("9511205432"),
                    "NIE", "NIE");
        });

        assertEquals(1, blockchain.getChain().size());
    }

    @Test
    void shouldNotAllowClosingPollsTwice(){
       

        blockchain.closePollsAndRevealAll();

        assertFalse(blockchain.isPollsOpen());
        assertThrows(IllegalStateException.class, blockchain::closePollsAndRevealAll);
    }

    @Test
    void shouldMarkAnswerOutsideBallotAsInvalid() {
       

        int idx = castVote( generateValidPesel("9905151234"), "MOZE", "MOZE");

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


    @Test
    void shouldCorrectlyCountValidAndInvalidVotes(){
        assertEquals(ANSWERS, blockchain.getAllowedAnswers());

        castVote( generateValidPesel("9905151234"), "TAK", "TAK");
        castVote( generateValidPesel("9511205432"), "NIE", "NIE");
        castVote( generateValidPesel("0122149876"), "TAK", "TAK");
        castVote( generateValidPesel("9001011234"), "TAK", "NIE");

        blockchain.closePollsAndRevealAll();

        assertEquals(2, blockchain.countVotes().get("TAK"));
        assertEquals(1, blockchain.countVotes().get("NIE"));
        assertEquals(1, blockchain.countInvalidBallots());
    }

    @Test
    void shouldRejectDuplicateBallotCommitmentOnBlockchain() {
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment("TAK", salt);
        BigInteger cleanSig = signCommitment(generateValidPesel("9905151234"), commitmentX);
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        blockchain.submitBallot(commitmentX, cleanSig, encryptedOpening);

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(commitmentX, cleanSig, encryptedOpening));
    }

    @Test
    void shouldHandleCorruptedEncryptedPayloadAndFormatBlockStatus() {
        int validIdx = castVote(generateValidPesel("9905151234"), "TAK", "TAK");
        assertEquals("[SEALED]", blockchain.getChain().get(validIdx).formatStatus());

        BigInteger commitmentX = VoteCommitment.createCommitment("NIE", VoteCommitment.generateSalt());
        BigInteger cleanSig = signCommitment(generateValidPesel("9511205432"), commitmentX);
        int corruptedIdx = blockchain.submitBallot(commitmentX, cleanSig, BigInteger.valueOf(12345));

        blockchain.closePollsAndRevealAll();

        assertEquals("TAK", blockchain.getChain().get(validIdx).formatStatus());
        assertTrue(blockchain.getChain().get(corruptedIdx).formatStatus().startsWith("[INVALID:"));
    }

    @Test
    void shouldRejectPeselWithInvalidMonthOrCalendarDate(){
        LocalDate electionDay = LocalDate.of(2026, 10, 24);

        String invalidFeb31 = generateValidPesel("9902311234");
        String invalidMonth = generateValidPesel("9965151234");
        String century1800 = generateValidPesel("9085151234");
        String century2100 = generateValidPesel("0545151234");

        assertFalse(PeselValidator.isAdultVoter(invalidFeb31, electionDay));
        assertFalse(PeselValidator.isAdultVoter(invalidMonth, electionDay));
        assertTrue(PeselValidator.isAdultVoter(century1800, electionDay));
        assertFalse(PeselValidator.isAdultVoter(century2100, electionDay));
    }

    @Test
    void shouldRejectBlankVoteOrSaltInCommitment(){
        assertThrows(IllegalArgumentException.class, () -> VoteCommitment.createCommitment("", "salt123"));
        assertThrows(IllegalArgumentException.class, () -> VoteCommitment.createCommitment("TAK", " "));
        assertThrows(IllegalArgumentException.class, () -> VoteCommitment.createCommitment(null, "salt123"));
    }

}





















