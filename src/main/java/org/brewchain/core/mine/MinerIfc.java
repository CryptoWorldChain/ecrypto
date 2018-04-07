package org.brewchain.core.mine;

import com.google.common.util.concurrent.ListenableFuture;
import org.brewchain.core.core.Block;
import org.brewchain.core.core.BlockHeader;

import static org.brewchain.core.util.ByteUtil.longToBytes;

/**
 * Mine algorithm interface
 */
public interface MinerIfc {

    /**
     * Starts mining the block. On successful mining the Block is update with necessary nonce and hash.
     * @return MiningResult Future object. The mining can be canceled via this Future. The Future is complete
     * when the block successfully mined.
     */
    ListenableFuture<MiningResult> mine(Block block);

    /**
     * Validates the Proof of Work for the block
     */
    boolean validate(BlockHeader blockHeader);

    final class MiningResult {

        public final long nonce;

        public final byte[] digest;

        /**
         * Mined block
         */
        public final Block block;

        public MiningResult(long nonce, byte[] digest, Block block) {
            this.nonce = nonce;
            this.digest = digest;
            this.block = block;
        }
    }
}
