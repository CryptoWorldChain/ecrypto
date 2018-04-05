package org.brewchain.core.jsonrpc;

import org.brewchain.core.core.Block;
import org.brewchain.core.core.TransactionInfo;

import static org.brewchain.core.jsonrpc.TypeConverter.toJsonHex;

public class TransactionReceiptDTOExt extends TransactionReceiptDTO {

    public String returnData;
    public String error;

    public TransactionReceiptDTOExt(Block block, TransactionInfo txInfo) {
        super(block, txInfo);
        returnData = toJsonHex(txInfo.getReceipt().getExecutionResult());
        error = txInfo.getReceipt().getError();
    }
}
