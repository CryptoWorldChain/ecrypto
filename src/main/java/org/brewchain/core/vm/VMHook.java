package org.brewchain.core.vm;

import org.brewchain.core.vm.program.Program;

public interface VMHook {
    void startPlay(Program program);
    void step(Program program, OpCode opcode);
    void stopPlay(Program program);
}
