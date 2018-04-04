package org.brewchain.core.config.net;

import org.brewchain.core.config.blockchain.FrontierConfig;
import org.brewchain.core.config.blockchain.HomesteadConfig;

public class TestNetConfig extends BaseNetConfig {
    public TestNetConfig() {
        add(0, new FrontierConfig());
        add(1_150_000, new HomesteadConfig());
    }
}
