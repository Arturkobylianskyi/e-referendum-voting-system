package ereferendum;

import ereferendum.crypto.BlindSignatureMath;
import ereferendum.crypto.VoteCommitment;
import ereferendum.service.ElectionAdmin;
import ereferendum.service.PeselValidator;
import ereferendum.service.VotingBlockchain;

import java.math.BigInteger;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Main {

    // Represents the client application on a voter's pc
    static class VoterClient{
        final String pesel;
        final String candidate;
        final String salt;
        final BigInteger commitmentX;

        BigInteger blindFactorB;
        BigInteger cleanSignature;
        int blockIndex;

        public VoterClient(String pesel, String candidate){
            this.pesel = pesel;
            this.candidate = candidate;
            this.salt = VoteCommitment.generateSalt();
            this.commitmentX = VoteCommitment.createCommitment(candidate, salt);
        }
    }

    // helper valid pesel generator
    private static String generateValidPesel(String first10Digits){
        return PeselValidator.generateValidPesel(first10Digits);
    }

    public static void main(String[] args){

        LocalDate electionDay = LocalDate.now();

        ElectionAdmin admin = new ElectionAdmin(electionDay);
        VotingBlockchain blockchain = new VotingBlockchain(admin.getModulusN(), admin.getPubExponentE(), List.of("TAK", "NIE"));

        List<VoterClient> voters = new ArrayList<>(List.of(
                new VoterClient(generateValidPesel("9905151234"), "TAK"),
                new VoterClient(generateValidPesel("9511205432"), "NIE"),
                new VoterClient(generateValidPesel("0324106789"), "TAK")
        ));

        System.out.println("Phase 1 Registration and blind signature ");
        for(VoterClient v : voters){
            // Voter masks their vote hash x * b^e mod N
            v.blindFactorB = BlindSignatureMath.generateBlindFactor(admin.getModulusN());
            BigInteger blindedMsg =  BlindSignatureMath.blind(
                    v.commitmentX, v.blindFactorB, admin.getPubExponentE(), admin.getModulusN()
            );

            // 2. admin verifies Pesel and signs blindly (x * b^e) ^d mod N
            BigInteger blindSig = admin.authorizeAndSign(v.pesel, blindedMsg);

            // 3. Voter removes mask b to get clean signature: x^d mod N
            v.cleanSignature = BlindSignatureMath.unblind(
                    blindSig, v.blindFactorB, admin.getModulusN()
            );
            System.out.println("[OK] Voter (Pesel: " + v.pesel + ") authorized and unblinded signature.");
        }

        System.out.println("Phase 2 Anonymous commit to blockchain");
        // Shuffle order to simulate anonymous network
        Collections.shuffle(voters);

        for(VoterClient v: voters){
            // Voter send only (commitmentX, cleanSignature) - no pesel
            BigInteger encryptedOpening = VoteCommitment.encryptOpening(
                    v.candidate, v.salt, blockchain.getTallyPubExponentE(), blockchain.getTallyModulusN()
            );

            v.blockIndex = blockchain.submitBallot(v.commitmentX, v.cleanSignature, encryptedOpening );
            System.out.println("[OK] Anonymous sealed ballot stored in ereferendum.model.Block #" + v.blockIndex);
        }

        blockchain.printResult();

        System.out.println("Phase 3: Anonymous reveal after referendum");

        blockchain.closePollsAndRevealAll();
        System.out.println("[OK] Polls closed ! Blockchain decrypted and verified all ballots.");

        System.out.println("Phase 4: Final election count");
        blockchain.printResult();



    }
}



















