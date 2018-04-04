package org.brewchain.core.validator;

import org.brewchain.core.config.Constants;
import org.brewchain.core.config.SystemProperties;
import org.brewchain.core.core.BlockHeader;

/**
 * Checks {@link BlockHeader#extraData} size against {@link Constants#getMAXIMUM_EXTRA_DATA_SIZE}
 *
 */
public class ExtraDataRule extends BlockHeaderRule {

    private final int MAXIMUM_EXTRA_DATA_SIZE;

    public ExtraDataRule(SystemProperties config) {
        MAXIMUM_EXTRA_DATA_SIZE = config.getBlockchainConfig().
                getCommonConstants().getMAXIMUM_EXTRA_DATA_SIZE();
    }

    @Override
    public ValidationResult validate(BlockHeader header) {
        if (header.getExtraData() != null && header.getExtraData().length > MAXIMUM_EXTRA_DATA_SIZE) {
            return fault(String.format(
                    "#%d: header.getExtraData().length > MAXIMUM_EXTRA_DATA_SIZE",
                    header.getNumber()
            ));
        }

        return Success;
    }
}
