package org.brewchain.core.mine;

import org.brewchain.core.core.Block;

public interface MinerListener {
    void miningStarted();
    void miningStopped();
    void blockMiningStarted(Block block);
    void blockMined(Block block);
    void blockMiningCanceled(Block block);
}
