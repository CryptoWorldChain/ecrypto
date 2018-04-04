package org.brewchain.core.net.eth.message;

import org.brewchain.core.net.message.Message;

public abstract class EthMessage extends Message {

    public EthMessage() {
    }

    public EthMessage(byte[] encoded) {
        super(encoded);
    }

    abstract public EthMessageCodes getCommand();
}
