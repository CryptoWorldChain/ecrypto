package org.brewchain.core;

import java.io.IOException;
import java.net.URISyntaxException;

import org.apache.commons.lang3.StringUtils;
import org.brewchain.core.cli.CLIInterface;
import org.brewchain.core.config.SystemProperties;
import org.brewchain.core.facade.Ethereum;
import org.brewchain.core.facade.EthereumFactory;
import org.brewchain.core.mine.Ethash;

public class Start {

    public static void main(String args[]) throws IOException, URISyntaxException {
        CLIInterface.call(args);

        final SystemProperties config = SystemProperties.getDefault();
        final boolean actionBlocksLoader = !config.blocksLoader().equals("");
        final boolean actionGenerateDag = !StringUtils.isEmpty(System.getProperty("ethash.blockNumber"));

        if (actionBlocksLoader || actionGenerateDag) {
            config.setSyncEnabled(false);
            config.setDiscoveryEnabled(false);
        }

        if (actionGenerateDag) {
            new Ethash(config, Long.parseLong(System.getProperty("ethash.blockNumber"))).getFullDataset();
            // DAG file has been created, lets exit
            System.exit(0);
        } else {
            Ethereum ethereum = EthereumFactory.createEthereum();

            if (actionBlocksLoader) {
                ethereum.getBlockLoader().loadBlocks();
            }
        }
    }

}
