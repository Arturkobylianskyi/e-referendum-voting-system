package ereferendum.controller;

import ereferendum.dto.*;
import ereferendum.model.Referendum;
import ereferendum.service.ElectionAdmin;
import ereferendum.service.VotingBlockchain;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * REST controller exposing public, voter, and admin endpoints
 */
@RestController
@RequestMapping("/api/referendums")
public class ReferendumController {

    private final ElectionAdmin admin;
    private final VotingBlockchain blockchain;


    public ReferendumController(ElectionAdmin admin, VotingBlockchain blockchain){
        this.admin = admin;
        this.blockchain = blockchain;
    }

    // Public: list all referendums
    @GetMapping
    public List<Referendum> getAllReferendums(){
        return blockchain.getAllReferendums();
    }

    // Public: get full referendum details, public RSA keys, blockchain blocks, and results
    @GetMapping("/{id}")
    public ReferendumDetailsResponse getReferendumDetails(@PathVariable Long id){
        Referendum referendum = blockchain.getReferendum(id);
        List<BlockDto> blocks = blockchain.getBlocks(id).stream()
                                                        .map(BlockDto::from)
                                                        .toList();

        return new ReferendumDetailsResponse(
                referendum.getId(),
                referendum.getTitle(),
                referendum.getQuestion(),
                referendum.isPollsOpen(),
                referendum.getAllowedAnswers(),
                admin.getModulusN().toString(),
                admin.getPubExponentE().toString(),
                blockchain.getTallyModulusN().toString(),
                blockchain.getTallyPubExponentE().toString(),
                blockchain.isChainValid(id),
                blockchain.countVotes(id),
                blockchain.countInvalidBallots(id),
                blocks
        );
    }

    // Admin: create a new referendum
    @PostMapping
    public Referendum createReferendum(@RequestBody CreateReferendumRequest request){
        return blockchain.createReferendum(
                request.title(),
                request.question(),
                request.allowedAnswers()
        );
    }

    // Voter: request an RSA blind signature on a blinded vote commitment
    @PostMapping("/{id}/authorize")
    public BlindSignResponse authorizeAndSign(
            @PathVariable Long id,
            @RequestBody BlindSignRequest request,
            Principal principal,
            @RequestHeader(value = "X-Voter-Id", required = false) String headerVoterId
            ){
        String voterId = (principal != null) ? principal.getName() : headerVoterId;
        BigInteger blindedMsg = new BigInteger(request.blindedMessage());
        BigInteger blindSig = admin.authorizeAndSign(id, voterId, blindedMsg);

        return new BlindSignResponse(blindSig.toString());
    }

    // Public: submit an ublinded signed ballot to the referendum blockchain
    @PostMapping("/{id}/ballots")
    public Map<String, Integer> submitBallot(@PathVariable Long id, @RequestBody BallotSubmitRequest request){
        int blockIndex = blockchain.submitBallot(
                id,
                new BigInteger(request.commitmentX()),
                new BigInteger(request.cleanSignature()),
                new BigInteger(request.encryptedOpening())
        );

        return Map.of("blockIndex", blockIndex);
    }

    // Admin: close the referendum, automatically decrypt all ballots, and return final results
    @PostMapping("/{id}/close")
    public ReferendumDetailsResponse closeReferendum(@PathVariable Long id){
        blockchain.closePollsAndRevealAll(id);
        return getReferendumDetails(id);
    }




}


















