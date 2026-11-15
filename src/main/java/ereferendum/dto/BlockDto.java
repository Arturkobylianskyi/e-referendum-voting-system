package ereferendum.dto;


import ereferendum.model.Block;

/**
 * Public representation of a single block on the referendum blockchain.
 * @param index
 * @param previousHash
 * @param currentHash
 * @param commitmentHex
 * @param status
 */
public record BlockDto(
        int index,
        String previousHash,
        String currentHash,
        String commitmentHex,
        String status
) {

    public static BlockDto from(Block block){
        return new BlockDto(
                block.index,
                block.previousHash,
                block.currentHash,
                block.commitmentX.toString(16),
                block.formatStatus()
        );
    }
}
