package org.brewchain.ecrypto.test;

import java.math.BigInteger;
import java.util.Date;

import org.apache.commons.codec.binary.Hex;
import org.brewchain.core.crypto.jni.IPPCrypto;

public class TestEnc {

	public static void main(String[] args) {
		String str = "hello cwv";
		System.out.println(Hex.encodeHexString(str.getBytes()));
		System.out.println(new String(new byte[] { 0x4E, 0x47, 0x49, 0x42 }));
		try {
			IPPCrypto.loadLibrary();
		} catch (Throwable e) {
			e.printStackTrace();
		}

		IPPCrypto crypto = new IPPCrypto();
		long start = System.currentTimeMillis();
		System.out.println(start+":"+new Date(1529798400*1000L));
		
		BigInteger bi=new BigInteger("200200000000020000000000000000001000000100000000", 16).clearBit(4);
		System.out.println("bi.count="+bi.clearBit(136).clearBit(122)
				.clearBit(176).clearBit(59).clearBit(86).clearBit(188)
				.clearBit(227).bitCount());
		
		
	}
}
