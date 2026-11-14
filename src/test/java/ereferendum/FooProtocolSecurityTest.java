package ereferendum;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.VoteCommitment;
import ereferendum.model.Block;
import ereferendum.model.Referendum;
import ereferendum.model.VoterAuthorization;
import ereferendum.repository.BlockRepository;
import ereferendum.repository.ReferendumRepository;
import ereferendum.repository.VoteAuthorizationRepository;
import ereferendum.service.ElectionAdmin;
import ereferendum.service.VotingBlockchain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class FooProtocolSecurityTest {

    private static final Long REF_ID = 1L;
    private static final List<String> ANSWERS = List.of("TAK", "NIE");

    private ElectionAdmin admin;
    private VotingBlockchain blockchain;

    @BeforeEach
    void setUp() {
        ReferendumRepository referendumRepository = mock(ReferendumRepository.class);
        BlockRepository blockRepository = mock(BlockRepository.class);
        VoteAuthorizationRepository authRepository = mock(VoteAuthorizationRepository.class);

        List<Block> storedBlocks = new ArrayList<>();
        Set<String> authorizedVoters = new HashSet<>();

        when(referendumRepository.save(any(Referendum.class))).thenAnswer(inv -> inv.getArgument(0));
        when(blockRepository.findByReferendumIdOrderByIndexAsc(REF_ID)).thenReturn(storedBlocks);
        when(blockRepository.existsByReferendumIdAndCommitmentX(eq(REF_ID), any()))
                .thenAnswer(inv -> storedBlocks.stream().anyMatch(b -> b.commitmentX.equals(inv.getArgument(1))));
        when(blockRepository.save(any(Block.class))).thenAnswer(inv -> {
            Block b = inv.getArgument(0);
            storedBlocks.add(b);
            return b;
        });

        when(authRepository.existsByReferendumIdAndVoterId(eq(REF_ID), anyString()))
                .thenAnswer(inv -> authorizedVoters.contains(inv.getArgument(1)));
        when(authRepository.save(any(VoterAuthorization.class))).thenAnswer(inv -> {
            VoterAuthorization auth = inv.getArgument(0);
            authorizedVoters.add(auth.getVoterId());
            return auth;
        });

        admin = new ElectionAdmin(referendumRepository, authRepository);
        blockchain = new VotingBlockchain(admin, referendumRepository, blockRepository);

        Referendum referendum = blockchain.createReferendum("Referendum 2026", "Czy jesteś za?", ANSWERS);
        when(referendumRepository.findById(REF_ID)).thenReturn(Optional.of(referendum));
    }

    // Helper valid voterId generator
    private static String generateValidVoterId(String id) {
        return "voter-" + id;
    }

    private BigInteger signCommitment(String voterId, BigInteger commitmentX) {
        BigInteger maskB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
        BigInteger blindedMsg = BlindSignatureMath.blind(
                commitmentX, maskB, admin.getPubExponentE(), admin.getModulusN()
        );
        BigInteger blindSig = admin.authorizeAndSign(REF_ID, voterId, blindedMsg);

        return BlindSignatureMath.unblind(blindSig, maskB, admin.getModulusN());
    }

    // Helper: full voting flow for one voter, returns index of the block with the ballot
    private int castVote(String voterId, String committedCandidate, String encryptedCandidate) {
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment(committedCandidate, salt);
        BigInteger cleanSig = signCommitment(voterId, commitmentX);
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                encryptedCandidate, salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        return blockchain.submitBallot(REF_ID, commitmentX, cleanSig, encryptedOpening);
    }

    @Test
    void shouldRejectBlankVoterId() {
        assertThrows(SecurityException.class, () -> admin.authorizeAndSign(REF_ID, "", BigInteger.valueOf(12345)));
        assertThrows(SecurityException.class, () -> admin.authorizeAndSign(REF_ID, null, BigInteger.valueOf(12345)));
    }

    @Test
    void shouldBlockDoubleVotingWithSameVoterId() {
        String validVoterId = generateValidVoterId("9905151234");

        BigInteger firstSignature = admin.authorizeAndSign(REF_ID, validVoterId, BigInteger.valueOf(77777));
        assertNotNull(firstSignature);

        assertThrows(SecurityException.class,
                () -> admin.authorizeAndSign(REF_ID, validVoterId, BigInteger.valueOf(888888)));
    }

    @Test
    void shouldRejectBallotWithForgedAdminSignature() {
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment("TAK", salt);
        BigInteger forgedSignature = BigInteger.valueOf(999999999);
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(REF_ID, commitmentX, forgedSignature, encryptedOpening));
    }

    @Test
    void shouldMarkMismatchedBallotAsInvalid() {
        int idx = castVote(generateValidVoterId("9511205432"), "TAK", "NIE");

        assertDoesNotThrow(() -> blockchain.closePollsAndRevealAll(REF_ID));

        Block block = blockchain.getBlocks(REF_ID).get(idx);
        assertTrue(block.invalid);
        assertNull(block.revealedCandidate);
    }

    @Test
    void oneInvalidBallotShouldNotBlockCountingOfOthers() {
        int badIdx = castVote(generateValidVoterId("9511205432"), "TAK", "NIE");
        int goodIdx = castVote(generateValidVoterId("9905151234"), "TAK", "TAK");

        blockchain.closePollsAndRevealAll(REF_ID);

        assertTrue(blockchain.getBlocks(REF_ID).get(badIdx).invalid);
        assertEquals("TAK", blockchain.getBlocks(REF_ID).get(goodIdx).revealedCandidate);
        assertTrue(blockchain.isChainValid(REF_ID));
    }

    @Test
    void shouldSuccessfullyCompleteSingleClickVotingAndAutoReveal() {
        String voterId = generateValidVoterId("0122149876");
        int blockIndex = castVote(voterId, "TAK", "TAK");

        blockchain.closePollsAndRevealAll(REF_ID);

        assertEquals("TAK", blockchain.getBlocks(REF_ID).get(blockIndex).revealedCandidate);
        assertTrue(blockchain.isChainValid(REF_ID));
    }

    @Test
    void shouldRejectBallotForgedWithoutAdmin() {
        BigInteger fakeSignature = new BigInteger("123456789");
        BigInteger fakeCommitment = fakeSignature.modPow(admin.getPubExponentE(), admin.getModulusN());

        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", VoteCommitment.generateSalt(),
                blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(REF_ID, fakeCommitment, fakeSignature, encryptedOpening));
    }

    @Test
    void shouldRejectTrivialSignatureOne() {
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", VoteCommitment.generateSalt(),
                blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(REF_ID, BigInteger.ONE, BigInteger.ONE, encryptedOpening));
    }

    @Test
    void shouldKeepBallotsSealedWhilePollsOpen() {
        int idx = castVote(generateValidVoterId("9905151234"), "TAK", "TAK");

        assertTrue(blockchain.getReferendum(REF_ID).isPollsOpen());
        assertNull(blockchain.getBlocks(REF_ID).get(idx).revealedCandidate);
    }

    @Test
    void shouldRejectBallotAfterPollsClosed() {
        castVote(generateValidVoterId("9905151234"), "TAK", "TAK");
        BigInteger preSignedCommitment = VoteCommitment.createCommitment("NIE", "salt");
        BigInteger preSignedSig = signCommitment(generateValidVoterId("0122149876"), preSignedCommitment);

        blockchain.closePollsAndRevealAll(REF_ID);

        // Both new blind signature requests and late ballot submissions must be rejected
        assertThrows(SecurityException.class,
                () -> castVote(generateValidVoterId("9511205432"), "NIE", "NIE"));
        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(REF_ID, preSignedCommitment, preSignedSig, BigInteger.ONE));

        assertEquals(1, blockchain.getBlocks(REF_ID).size());
    }

    @Test
    void shouldNotAllowClosingPollsTwice() {
        blockchain.closePollsAndRevealAll(REF_ID);

        assertFalse(blockchain.getReferendum(REF_ID).isPollsOpen());
        assertThrows(IllegalStateException.class, () -> blockchain.closePollsAndRevealAll(REF_ID));
    }

    @Test
    void shouldMarkAnswerOutsideBallotAsInvalid() {
        int idx = castVote(generateValidVoterId("9905151234"), "MOZE", "MOZE");

        blockchain.closePollsAndRevealAll(REF_ID);

        assertTrue(blockchain.getBlocks(REF_ID).get(idx).invalid);
        assertNull(blockchain.getBlocks(REF_ID).get(idx).revealedCandidate);
    }

    @Test
    void shouldRejectInvalidReferendumParameters() {
        assertThrows(IllegalArgumentException.class, () -> blockchain.createReferendum("", "Pytanie?", ANSWERS));
        assertThrows(IllegalArgumentException.class, () -> blockchain.createReferendum("Tytuł", " ", ANSWERS));
        assertThrows(IllegalArgumentException.class, () -> blockchain.createReferendum("Tytuł", "Pytanie?", List.of("TAK")));
        assertThrows(IllegalArgumentException.class, () -> blockchain.createReferendum("Tytuł", "Pytanie?", List.of("TAK", "TAK")));
        assertThrows(IllegalArgumentException.class, () -> blockchain.createReferendum("Tytuł", "Pytanie?", List.of("TAK", "N:IE")));
        assertThrows(IllegalArgumentException.class, () -> blockchain.createReferendum("Tytuł", "Pytanie?", List.of("TAK", " ")));
    }

    @Test
    void shouldCorrectlyCountValidAndInvalidVotes() {
        assertEquals(ANSWERS, blockchain.getReferendum(REF_ID).getAllowedAnswers());

        castVote(generateValidVoterId("9905151234"), "TAK", "TAK");
        castVote(generateValidVoterId("9511205432"), "NIE", "NIE");
        castVote(generateValidVoterId("0122149876"), "TAK", "TAK");
        castVote(generateValidVoterId("9001011234"), "TAK", "NIE");

        blockchain.closePollsAndRevealAll(REF_ID);

        assertEquals(2, blockchain.countVotes(REF_ID).get("TAK"));
        assertEquals(1, blockchain.countVotes(REF_ID).get("NIE"));
        assertEquals(1, blockchain.countInvalidBallots(REF_ID));
    }

    @Test
    void shouldRejectDuplicateBallotCommitmentOnBlockchain() {
        String salt = VoteCommitment.generateSalt();
        BigInteger commitmentX = VoteCommitment.createCommitment("TAK", salt);
        BigInteger cleanSig = signCommitment(generateValidVoterId("9905151234"), commitmentX);
        BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                "TAK", salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
        );

        blockchain.submitBallot(REF_ID, commitmentX, cleanSig, encryptedOpening);

        assertThrows(SecurityException.class,
                () -> blockchain.submitBallot(REF_ID, commitmentX, cleanSig, encryptedOpening));
    }

    @Test
    void shouldHandleCorruptedEncryptedPayloadAndFormatBlockStatus() {
        int validIdx = castVote(generateValidVoterId("9905151234"), "TAK", "TAK");
        assertEquals("[SEALED]", blockchain.getBlocks(REF_ID).get(validIdx).formatStatus());

        BigInteger commitmentX = VoteCommitment.createCommitment("NIE", VoteCommitment.generateSalt());
        BigInteger cleanSig = signCommitment(generateValidVoterId("9511205432"), commitmentX);
        int corruptedIdx = blockchain.submitBallot(REF_ID, commitmentX, cleanSig, BigInteger.valueOf(12345));

        blockchain.closePollsAndRevealAll(REF_ID);

        assertEquals("TAK", blockchain.getBlocks(REF_ID).get(validIdx).formatStatus());
        assertTrue(blockchain.getBlocks(REF_ID).get(corruptedIdx).formatStatus().startsWith("[INVALID:"));
    }

    @Test
    void shouldRejectBlankVoteOrSaltInCommitment() {
        assertThrows(IllegalArgumentException.class, () -> VoteCommitment.createCommitment("", "salt123"));
        assertThrows(IllegalArgumentException.class, () -> VoteCommitment.createCommitment("TAK", " "));
        assertThrows(IllegalArgumentException.class, () -> VoteCommitment.createCommitment(null, "salt123"));
    }
}