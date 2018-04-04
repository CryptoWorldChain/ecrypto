package org.brewchain.core.validator;

import org.brewchain.core.config.SystemProperties;
import org.brewchain.core.core.BlockHeader;

import java.math.BigInteger;

import static org.brewchain.core.util.BIUtil.isEqual;

/**
 * Checks block's difficulty against calculated difficulty value
 *
 */
public class DifficultyRule extends DependentBlockHeaderRule {

    private final SystemProperties config;

    public DifficultyRule(SystemProperties config) {
        this.config = config;
    }

    @Override
    public boolean validate(BlockHeader header, BlockHeader parent) {

        errors.clear();

        BigInteger calcDifficulty = header.calcDifficulty(config.getBlockchainConfig(), parent);
        BigInteger difficulty = header.getDifficultyBI();

        if (!isEqual(difficulty, calcDifficulty)) {

            errors.add(String.format("#%d: difficulty != calcDifficulty", header.getNumber()));
            return false;
        }

        return true;
    }
}
