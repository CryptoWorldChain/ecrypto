package org.brewchain.core.vm.program.listener;

import org.brewchain.core.vm.DataWord;

public interface ProgramListener {

    void onMemoryExtend(int delta);

    void onMemoryWrite(int address, byte[] data, int size);

    void onStackPop();

    void onStackPush(DataWord value);

    void onStackSwap(int from, int to);

    void onStoragePut(DataWord key, DataWord value);

    void onStorageClear();
}