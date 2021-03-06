package org.brewchain.ecrypto.test;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.brewchain.core.crypto.jni.IPPCrypto;
import org.brewchain.core.util.EndianHelper;

import javassist.bytecode.ByteArray;

public class TestIPPCWV {

	public static void main(String[] args) {
		try {
			IPPCrypto.loadLibrary();
		} catch (Throwable e) {
			e.printStackTrace();
		}
		IPPCrypto crypto = new IPPCrypto();
		// for (int i = 0; i < 1; i++) {
		// byte[] pk = new byte[32];
		// byte[] x = new byte[32];
		// byte[] y = new byte[32];
		//
		// byte[] s = new byte[32];
		// byte[] a = new byte[32];
		// byte[] msg = ("hello cwv 2018-06:" +
		// System.currentTimeMillis()).getBytes();
		//
		// byte[] seed = null;
		// if (false) {// 非随机种子
		// seed = new byte[8];
		// // ByteArray.write32bit((int)System.currentTimeMillis(), seed,
		// // 0);
		// // ByteArray.write32bit((int)System.nanoTime(), seed, 4);
		// ByteArray.write32bit(100, seed, 0);
		// ByteArray.write32bit(300, seed, 4);
		// System.out.println("Seed=" + Hex.encodeHexString(seed));
		// }
		// crypto.genKeys(seed, pk, x, y);
		//
		// byte[] x1 = new byte[32];
		// byte[] y1 = new byte[32];
		//
		// if (crypto.fromPrikey(pk, x1, y1)) {
		// System.out.println("from prikey okok");
		// }
		// if (crypto.signMessage(pk, x, y, msg, s, a)) {
		// System.out.println("Sign OKOK");
		// }
		//
		// if (crypto.verifyMessage(x, y, msg, s, a)) {
		// System.out.println("verify OKOK");
		// }
		// long start = System.currentTimeMillis();
		// // for(int i=0;i<10000;i++){
		// // crypto.verifyMessage(x, y, msg, s, a);
		// // }
		// System.out.println("p=" + Hex.encodeHexString(pk));
		// System.out.println("x=" + Hex.encodeHexString(x));
		// // System.out.println("x1="+Hex.encodeHexString(x1));
		// System.out.println("y=" + Hex.encodeHexString(y));
		// // System.out.println("y1="+Hex.encodeHexString(y1));
		// // System.out.println("s="+Hex.encodeHexString(s));
		// // System.out.println("a="+Hex.encodeHexString(a));
		// System.out.println("cost=" + (System.currentTimeMillis() - start));
		// //
		// }
		//
		// byte[] bb = "testby您好te".getBytes();
		// byte [] bsha256=new byte[32];
		// byte [] bsha3=new byte[32];
		// byte [] bmd5=new byte[16];
		// byte [] bkeccak=new byte[32];
		// for (int i = 0; i < 1; i++) {
		// crypto.sha256(bb);
		// crypto.sha3(bb);
		// crypto.md5(bb);
		// crypto.keccak(bb);
		//
		// crypto.bsha256(bb,bsha256);
		// crypto.bsha3(bb,bsha3);
		// crypto.bmd5(bb,bmd5);
		// crypto.bkeccak(bb,bkeccak);
		//
		//// System.out.println("sha256="+crypto.sha256(bb).equals(Hex.encodeHexString(bsha256))+"=>"
		// + crypto.sha256(bb)+","+Hex.encodeHexString(bsha256));
		//// System.out.println("sha3="
		// +crypto.sha3(bb).equals(Hex.encodeHexString(bsha3))+"=>"+
		// crypto.sha3(bb)+","+Hex.encodeHexString(bsha3));
		//// System.out.println("md5="
		// +crypto.md5(bb).equals(Hex.encodeHexString(bmd5))+"=>"+
		// crypto.md5(bb)+","+Hex.encodeHexString(bmd5));
		//// System.out.println("keccak="+crypto.keccak(bb).equals(Hex.encodeHexString(bkeccak))+"=>"
		// + crypto.keccak(bb)+","+Hex.encodeHexString(bkeccak));
		// }
		try {
			String pri_o = "0e75a8a392804c08b60011751abbd8840630210eb80ffe57cd51063103728e03";
//			String pri = "";
//			for (int i = 0; i < pri_o.length(); i += 2) {
//				pri = pri + pri_o.substring(pri_o.length() - 2 - i, pri_o.length() - i);
//			}
//			System.out.println("pri=" + pri);

			byte x[] = new byte[32];
			byte y[] = new byte[32];
			byte p[] = Hex.decodeHex("5e2275148cc0f545171cf53402666f9ea4405ae4214a3e125a68485c0948f546".toCharArray());
			byte p1[] = EndianHelper.revert(Hex.decodeHex(pri_o.toCharArray()));
//			System.out.println("str.p=" + Hex.encodeHexString(p));
			System.out.println("str.p1=" + Hex.encodeHexString(p1));

			crypto.fromPrikey(p, x, y);
//			crypto.fromPrikey(p1, x, y);
			System.out.println("pubkey,x=" + Hex.encodeHexString(EndianHelper.revert(x)) + ",y=" + Hex.encodeHexString(EndianHelper.revert(y)));
		} catch (DecoderException e) {
			e.printStackTrace();
		}
	}

}
