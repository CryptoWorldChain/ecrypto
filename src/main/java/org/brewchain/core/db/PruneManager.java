package org.brewchain.core.db;

import org.brewchain.core.config.SystemProperties;
import org.brewchain.core.core.Block;
import org.brewchain.core.core.BlockHeader;
import org.brewchain.core.datasource.JournalSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class PruneManager {

    private JournalSource journal;

    @Autowired
    private IndexedBlockStore blockStore;

    private int pruneBlocksCnt;

    @Autowired
    private PruneManager(SystemProperties config) {
        pruneBlocksCnt = config.databasePruneDepth();
    }

    public PruneManager(IndexedBlockStore blockStore, JournalSource journal, int pruneBlocksCnt) {
        this.blockStore = blockStore;
        this.journal = journal;
        this.pruneBlocksCnt = pruneBlocksCnt;
    }

    @Autowired
    public void setStateSource(StateSource stateSource) {
        journal = stateSource.getJournalSource();
    }

    public void blockCommitted(BlockHeader block) {
        if (pruneBlocksCnt < 0) return; // pruning disabled

        journal.commitUpdates(block.getHash());
        long pruneBlockNum = block.getNumber() - pruneBlocksCnt;
        if (pruneBlockNum < 0) return;

        List<Block> pruneBlocks = blockStore.getBlocksByNumber(pruneBlockNum);
        Block chainBlock = blockStore.getChainBlockByNumber(pruneBlockNum);
        for (Block pruneBlock : pruneBlocks) {
            if (journal.hasUpdate(pruneBlock.getHash())) {
                if (chainBlock.isEqual(pruneBlock)) {
                    journal.persistUpdate(pruneBlock.getHash());
                } else {
                    journal.revertUpdate(pruneBlock.getHash());
                }
            }
        }
    }
}
