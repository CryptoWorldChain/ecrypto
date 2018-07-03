package org.brewchain.ecrypto.test;

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

	}
}
