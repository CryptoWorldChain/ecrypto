package org.brewchain.core.config.net;

import org.brewchain.core.config.blockchain.*;

public class RopstenNetConfig extends BaseNetConfig {

    public RopstenNetConfig() {
        add(0, new HomesteadConfig());
        add(10, new RopstenConfig(new HomesteadConfig()));
        add(1_700_000, new RopstenConfig(new ByzantiumConfig(new DaoHFConfig())));
    }
}
