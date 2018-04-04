package org.brewchain.core.util.blockchain;

import org.brewchain.core.core.CallTransaction;

public interface SolidityFunction {

    SolidityContract getContract();

    CallTransaction.Function getInterface();
}
