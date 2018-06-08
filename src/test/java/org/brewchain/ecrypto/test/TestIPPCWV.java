package org.brewchain.ecrypto.test;

import org.apache.commons.codec.binary.Hex;
import org.brewchain.core.crypto.jni.IPPCrypto;


public class TestIPPCWV {

	public static void main(String[] args) {
		IPPCrypto.loadLibrary();
		IPPCrypto crypto = new IPPCrypto();
		
		byte []pk=new byte[32];
		byte []x=new byte[32];
		byte []y=new byte[32];
		
		byte []s=new byte[32];
		byte []a=new byte[32];
		byte []msg = ("hello cwv 2018-06:"+System.currentTimeMillis()).getBytes();
		
		crypto.genKeys(pk, x, y);
		
		byte []x1=new byte[32];
		byte []y1=new byte[32];

		if(crypto.fromPrikey(pk, x1, y1)){
			System.out.println("from prikey okok");
		}
		if(crypto.signMessage(pk, x, y, msg, s, a)){
			System.out.println("Sign OKOK");
		}
		
		if(crypto.verifyMessage(x, y, msg, s, a)){
			System.out.println("verify OKOK");
		}

		System.out.println("p="+Hex.encodeHexString(pk));
		System.out.println("x="+Hex.encodeHexString(x));
		System.out.println("x1="+Hex.encodeHexString(x1));
		System.out.println("y="+Hex.encodeHexString(y));
		System.out.println("y1="+Hex.encodeHexString(y1));
		System.out.println("s="+Hex.encodeHexString(s));
		System.out.println("a="+Hex.encodeHexString(a));
//		
		
	}

}
