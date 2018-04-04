package org.brewchain.core.samples;

import com.typesafe.config.ConfigFactory;
import org.brewchain.core.config.SystemProperties;
import org.brewchain.core.crypto.ECKey;
import org.brewchain.core.crypto.HashUtil;
import org.brewchain.core.facade.Ethereum;
import org.brewchain.core.facade.EthereumFactory;
import org.springframework.context.annotation.Bean;

/**
 * This class just extends the BasicSample with the config which connect the peer to the Morden network
 * This class can be used as a base for free transactions testing
 * Everyone may use that 'cow' sender (which is effectively address aacc23ff079d96a5502b31fefcda87a6b3fbdcfb)
 * If you need more coins on this account just go to https://morden.ether.camp/
 * and push 'Get Free Ether' button.
 *
 */
public class RopstenSample extends BasicSample {
    /**
     * Use that sender key to sign transactions
     */
    protected final byte[] senderPrivateKey = HashUtil.sha3("cow".getBytes());
    // sender address is derived from the private key aacc23ff079d96a5502b31fefcda87a6b3fbdcfb
    protected final byte[] senderAddress = ECKey.fromPrivate(senderPrivateKey).getAddress();

    protected abstract static class RopstenSampleConfig {
        private final String config =
                "peer.discovery = {" +
                "    enabled = true \n" +
                "    ip.list = [" +
                "        '94.242.229.4:40404'," +
                "        '94.242.229.203:30303'" +
                "    ]" +
                "} \n" +
                "peer.p2p.eip8 = true \n" +
                "peer.networkId = 3 \n" +
                "sync.enabled = true \n" +
                "genesis = ropsten.json \n" +
                "blockchain.config.name = 'ropsten' \n" +
                "database.dir = database-ropstenSample";

        public abstract RopstenSample sampleBean();

        @Bean
        public SystemProperties systemProperties() {
            SystemProperties props = new SystemProperties();
            props.overrideParams(ConfigFactory.parseString(config.replaceAll("'", "\"")));
            return props;
        }
    }

    public static void main(String[] args) throws Exception {
        sLogger.info("Starting EthereumJ!");

        class SampleConfig extends RopstenSampleConfig {
            @Bean
            public RopstenSample sampleBean() {
                return new RopstenSample();
            }
        }

        Ethereum ethereum = EthereumFactory.createEthereum(SampleConfig.class);
    }
}
