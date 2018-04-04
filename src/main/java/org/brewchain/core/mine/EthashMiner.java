package org.brewchain.core.mine;

import com.google.common.util.concurrent.ListenableFuture;
import org.brewchain.core.config.SystemProperties;
import org.brewchain.core.core.Block;
import org.brewchain.core.core.BlockHeader;

/**
 * The adapter of Ethash for MinerIfc
 */
public class EthashMiner implements MinerIfc {

    SystemProperties config;

    private int cpuThreads;
    private boolean fullMining = true;

    public EthashMiner(SystemProperties config) {
        this.config = config;
        cpuThreads = config.getMineCpuThreads();
        fullMining = config.isMineFullDataset();
    }

    @Override
    public ListenableFuture<MiningResult> mine(Block block) {
        return fullMining ?
                Ethash.getForBlock(config, block.getNumber()).mine(block, cpuThreads) :
                Ethash.getForBlock(config, block.getNumber()).mineLight(block, cpuThreads);
    }

    @Override
    public boolean validate(BlockHeader blockHeader) {
        return Ethash.getForBlock(config, blockHeader.getNumber()).validate(blockHeader);
    }
}
