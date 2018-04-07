package org.brewchain.core.net.shh;

import org.brewchain.core.db.ByteArrayWrapper;
import org.brewchain.core.util.RLP;
import org.brewchain.core.util.RLPList;
import org.spongycastle.util.encoders.Hex;

import static org.brewchain.core.net.shh.ShhMessageCodes.FILTER;

public class ShhFilterMessage extends ShhMessage {

    private byte[] bloomFilter;

    private ShhFilterMessage() {
    }

    public ShhFilterMessage(byte[] encoded) {
        super(encoded);
        parse();
    }

    static ShhFilterMessage createFromFilter(byte[] bloomFilter) {
        ShhFilterMessage ret = new ShhFilterMessage();
        ret.bloomFilter = bloomFilter;
        ret.parsed = true;
        return ret;
    }

    private void encode() {
        byte[] protocolVersion = RLP.encodeElement(this.bloomFilter);
        this.encoded = RLP.encodeList(protocolVersion);
    }

    private void parse() {
        RLPList paramsList = (RLPList) RLP.decode2(encoded).get(0);
        this.bloomFilter = paramsList.get(0).getRLPData();
        parsed = true;
    }

    @Override
    public byte[] getEncoded() {
        if (encoded == null) encode();
        return encoded;
    }

    public byte[] getBloomFilter() {
        return bloomFilter;
    }

    @Override
    public Class<?> getAnswerMessage() {
        return null;
    }

    @Override
    public ShhMessageCodes getCommand() {
        return FILTER;
    }

    @Override
    public String toString() {
        if (!parsed) parse();
        return "[" + this.getCommand().name() +
            " hash=" + Hex.toHexString(bloomFilter) + "]";
    }

}
