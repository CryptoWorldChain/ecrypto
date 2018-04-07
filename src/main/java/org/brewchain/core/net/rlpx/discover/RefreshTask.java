package org.brewchain.core.net.rlpx.discover;

import java.util.ArrayList;
import java.util.Random;

import org.brewchain.core.net.rlpx.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RefreshTask extends DiscoverTask {
    private static final Logger logger = LoggerFactory.getLogger("discover");

    public RefreshTask(NodeManager nodeManager) {
        super(nodeManager);
    }
//
//    RefreshTask(Channel channel, ECKey key, NodeTable table) {
//        super(getNodeId(), channel, key, table);
//    }

    public static byte[] getNodeId() {
        Random gen = new Random();
        byte[] id = new byte[64];
        gen.nextBytes(id);
        return id;
    }

    @Override
    public void run() {
        discover(getNodeId(), 0, new ArrayList<Node>());
    }
}
