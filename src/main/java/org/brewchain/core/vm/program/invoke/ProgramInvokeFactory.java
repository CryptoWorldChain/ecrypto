package org.brewchain.core.vm.program.invoke;

import org.brewchain.core.core.Block;
import org.brewchain.core.core.Repository;
import org.brewchain.core.core.Transaction;
import org.brewchain.core.db.BlockStore;
import org.brewchain.core.vm.DataWord;
import org.brewchain.core.vm.program.Program;

import java.math.BigInteger;

public interface ProgramInvokeFactory {

    ProgramInvoke createProgramInvoke(Transaction tx, Block block,
                                      Repository repository, BlockStore blockStore);

    ProgramInvoke createProgramInvoke(Program program, DataWord toAddress, DataWord callerAddress,
                                             DataWord inValue, DataWord inGas,
                                             BigInteger balanceInt, byte[] dataIn,
                                             Repository repository, BlockStore blockStore,
                                            boolean staticCall, boolean byTestingSuite);


}
