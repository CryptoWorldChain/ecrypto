package org.brewchain.core.jsonrpc;

import org.brewchain.core.core.Block;
import org.brewchain.core.core.TransactionReceipt;
import org.brewchain.core.core.TransactionInfo;
import org.brewchain.core.util.ByteUtil;
import org.brewchain.core.vm.LogInfo;

import static org.brewchain.core.jsonrpc.TypeConverter.toJsonHex;

public class TransactionReceiptDTO {

    public String transactionHash;  // hash of the transaction.
    public int transactionIndex;    // integer of the transactions index position in the block.
    public String blockHash;        // hash of the block where this transaction was in.
    public long blockNumber;         // block number where this transaction was in.
    public long cumulativeGasUsed;   // The total amount of gas used when this transaction was executed in the block.
    public long gasUsed;             //The amount of gas used by this specific transaction alone.
    public String contractAddress; // The contract address created, if the transaction was a contract creation, otherwise  null .
    public JsonRpc.LogFilterElement[] logs;         // Array of log objects, which this transaction generated.

    public  TransactionReceiptDTO(Block block, TransactionInfo txInfo){
        TransactionReceipt receipt = txInfo.getReceipt();

        transactionHash = toJsonHex(receipt.getTransaction().getHash());
        transactionIndex = txInfo.getIndex();
        cumulativeGasUsed = ByteUtil.byteArrayToLong(receipt.getCumulativeGas());
        gasUsed = ByteUtil.byteArrayToLong(receipt.getGasUsed());
        if (receipt.getTransaction().getContractAddress() != null)
            contractAddress = toJsonHex(receipt.getTransaction().getContractAddress());
        logs = new JsonRpc.LogFilterElement[receipt.getLogInfoList().size()];
        if (block != null) {
            blockNumber = block.getNumber();
            blockHash = toJsonHex(txInfo.getBlockHash());
            for (int i = 0; i < logs.length; i++) {
                LogInfo logInfo = receipt.getLogInfoList().get(i);
                logs[i] = new JsonRpc.LogFilterElement(logInfo, block, txInfo.getIndex(),
                        txInfo.getReceipt().getTransaction(), i);
            }
        }
    }
}
