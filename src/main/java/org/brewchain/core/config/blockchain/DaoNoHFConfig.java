package org.brewchain.core.config.blockchain;

import org.brewchain.core.config.BlockchainConfig;

public class DaoNoHFConfig extends AbstractDaoConfig {

    {
        supportFork = false;
    }

    public DaoNoHFConfig() {
        initDaoConfig(new HomesteadConfig(), ETH_FORK_BLOCK_NUMBER);
    }

    public DaoNoHFConfig(BlockchainConfig parent, long forkBlockNumber) {
        initDaoConfig(parent, forkBlockNumber);
    }

    @Override
    public String toString() {
        return super.toString() + "(forkBlock:" + forkBlockNumber + ")";
    }
}
