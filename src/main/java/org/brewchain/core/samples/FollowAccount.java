package org.brewchain.core.samples;

import org.brewchain.core.core.Block;
import org.brewchain.core.core.TransactionReceipt;
import org.brewchain.core.facade.Ethereum;
import org.brewchain.core.facade.EthereumFactory;
import org.brewchain.core.facade.Repository;
import org.brewchain.core.listener.EthereumListenerAdapter;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.List;

public class FollowAccount extends EthereumListenerAdapter {


    Ethereum ethereum = null;

    public FollowAccount(Ethereum ethereum) {
        this.ethereum = ethereum;
    }

    public static void main(String[] args) {

        Ethereum ethereum = EthereumFactory.createEthereum();
        ethereum.addListener(new FollowAccount(ethereum));
    }

    @Override
    public void onBlock(Block block, List<TransactionReceipt> receipts) {

        byte[] cow = Hex.decode("cd2a3d9f938e13cd947ec05abc7fe734df8dd826");

        // Get snapshot some time ago - 10% blocks ago
        long bestNumber = ethereum.getBlockchain().getBestBlock().getNumber();
        long oldNumber = (long) (bestNumber * 0.9);

        Block oldBlock = ethereum.getBlockchain().getBlockByNumber(oldNumber);

        Repository repository = ethereum.getRepository();
        Repository snapshot = ethereum.getSnapshotTo(oldBlock.getStateRoot());

        BigInteger nonce_ = snapshot.getNonce(cow);
        BigInteger nonce = repository.getNonce(cow);

        System.err.println(" #" + block.getNumber() + " [cd2a3d9] => snapshot_nonce:" +  nonce_ + " latest_nonce:" + nonce);
    }
}
