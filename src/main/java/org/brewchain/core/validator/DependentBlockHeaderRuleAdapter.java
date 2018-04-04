package org.brewchain.core.validator;

import org.brewchain.core.core.BlockHeader;

public class DependentBlockHeaderRuleAdapter extends DependentBlockHeaderRule {

    @Override
    public boolean validate(BlockHeader header, BlockHeader dependency) {
        return true;
    }
}
