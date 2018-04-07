package org.brewchain.core.config.net;

import org.brewchain.core.config.blockchain.Eip150HFConfig;
import org.brewchain.core.config.blockchain.Eip160HFConfig;
import org.brewchain.core.config.blockchain.MordenConfig;

public class MordenNetConfig extends BaseNetConfig {

    public MordenNetConfig() {
        add(0, new MordenConfig.Frontier());
        add(494_000, new MordenConfig.Homestead());
        add(1_783_000, new Eip150HFConfig(new MordenConfig.Homestead()));
        add(1_885_000, new Eip160HFConfig(new MordenConfig.Homestead()));

    }
}
