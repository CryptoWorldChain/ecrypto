package org.brewchain.core.config.blockchain;

import org.brewchain.core.config.Constants;
import org.brewchain.core.core.Transaction;

import java.math.BigInteger;

public class FrontierConfig extends OlympicConfig {

    public static class FrontierConstants extends Constants {
        private static final BigInteger BLOCK_REWARD = new BigInteger("5000000000000000000");

        @Override
        public int getDURATION_LIMIT() {
            return 13;
        }

        @Override
        public BigInteger getBLOCK_REWARD() {
            return BLOCK_REWARD;
        }

        @Override
        public int getMIN_GAS_LIMIT() {
            return 5000;
        }
    };

    public FrontierConfig() {
        this(new FrontierConstants());
    }

    public FrontierConfig(Constants constants) {
        super(constants);
    }


    @Override
    public boolean acceptTransactionSignature(Transaction tx) {
        if (!super.acceptTransactionSignature(tx)) return false;
        if (tx.getSignature() == null) return false;
        return tx.getSignature().validateComponents();
    }

}
