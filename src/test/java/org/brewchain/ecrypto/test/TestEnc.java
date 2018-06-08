package org.brewchain.ecrypto.test;

import org.apache.commons.codec.binary.Hex;

public class TestEnc {

	public static void main(String[] args) {
		String str="hello cwv";
	    System.out.println(Hex.encodeHexString(str.getBytes()));
	    System.out.println(new String(new byte[]{0x4E,0x47,0x49,0x42}));
	} 
}
