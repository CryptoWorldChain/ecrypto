package org.brewchain.core.config.blockchain;

import org.apache.commons.lang3.ArrayUtils;
import org.brewchain.core.config.Constants;
import org.brewchain.core.core.BlockHeader;
import org.brewchain.core.core.Transaction;

import java.math.BigInteger;

public class OlympicConfig extends AbstractConfig {

    public OlympicConfig() {
    }

    public OlympicConfig(Constants constants) {
        super(constants);
    }

    @Override
    public BigInteger getCalcDifficultyMultiplier(BlockHeader curBlock, BlockHeader parent) {
        return BigInteger.valueOf(curBlock.getTimestamp() >= parent.getTimestamp() +
                getConstants().getDURATION_LIMIT() ? -1 : 1);
    }

    @Override
    public long getTransactionCost(Transaction tx) {
        long nonZeroes = tx.nonZeroDataBytes();
        long zeroVals  = ArrayUtils.getLength(tx.getData()) - nonZeroes;

        return getGasCost().getTRANSACTION() + zeroVals * getGasCost().getTX_ZERO_DATA() +
                nonZeroes * getGasCost().getTX_NO_ZERO_DATA();
    }
}
