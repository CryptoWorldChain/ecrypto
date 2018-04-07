package org.brewchain.core.util.blockchain;

import org.brewchain.core.core.TransactionExecutionSummary;
import org.brewchain.core.core.TransactionReceipt;

public class TransactionResult {
    TransactionReceipt receipt;
    TransactionExecutionSummary executionSummary;

    public boolean isIncluded() {
        return receipt != null;
    }

    public TransactionReceipt getReceipt() {
        return receipt;
    }

    public TransactionExecutionSummary getExecutionSummary() {
        return executionSummary;
    }
}
