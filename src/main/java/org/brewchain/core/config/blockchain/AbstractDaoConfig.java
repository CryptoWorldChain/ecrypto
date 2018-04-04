package org.brewchain.core.config.blockchain;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.brewchain.core.config.BlockchainConfig;
import org.brewchain.core.core.BlockHeader;
import org.brewchain.core.core.Transaction;
import org.brewchain.core.validator.BlockHeaderRule;
import org.brewchain.core.validator.BlockHeaderValidator;
import org.brewchain.core.validator.ExtraDataPresenceRule;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public abstract class AbstractDaoConfig extends FrontierConfig {

    /**
     * Hardcoded values from live network
     */
    public static final long ETH_FORK_BLOCK_NUMBER = 1_920_000;
    // "dao-hard-fork" encoded message
    public static final byte[] DAO_EXTRA_DATA = Hex.decode("64616f2d686172642d666f726b");
    private final long EXTRA_DATA_AFFECTS_BLOCKS_NUMBER = 10;

    // MAYBE find a way to remove block number value from blockchain config
    protected long forkBlockNumber;

    // set in child classes
    protected boolean supportFork;

    private BlockchainConfig parent;

    protected void initDaoConfig(BlockchainConfig parent, long forkBlockNumber) {
        this.parent = parent;
        this.constants = parent.getConstants();
        this.forkBlockNumber = forkBlockNumber;
        BlockHeaderRule rule = new ExtraDataPresenceRule(DAO_EXTRA_DATA, supportFork);
        headerValidators().add(Pair.of(forkBlockNumber, new BlockHeaderValidator(rule)));
    }

    /**
     * Miners should include marker for initial 10 blocks. Either "dao-hard-fork" or ""
     */
    @Override
    public byte[] getExtraData(byte[] minerExtraData, long blockNumber) {
        if (blockNumber >= forkBlockNumber && blockNumber < forkBlockNumber + EXTRA_DATA_AFFECTS_BLOCKS_NUMBER ) {
            if (supportFork) {
                return DAO_EXTRA_DATA;
            } else {
                return new byte[0];
            }

        }
        return minerExtraData;
    }

    @Override
    public BigInteger calcDifficulty(BlockHeader curBlock, BlockHeader parent) {
        return this.parent.calcDifficulty(curBlock, parent);
    }

    @Override
    public long getTransactionCost(Transaction tx) {
        return parent.getTransactionCost(tx);
    }

    @Override
    public boolean acceptTransactionSignature(Transaction tx) {
        return parent.acceptTransactionSignature(tx);
    }

}
