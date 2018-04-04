package org.brewchain.core.facade;

import java.util.List;

import org.brewchain.core.core.Transaction;

public interface PendingState {

    /**
     * @return pending state repository
     */
    org.brewchain.core.core.Repository getRepository();

    /**
     * @return list of pending transactions
     */
    List<Transaction> getPendingTransactions();
}
