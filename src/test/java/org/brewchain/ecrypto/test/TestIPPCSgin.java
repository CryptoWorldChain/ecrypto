package org.brewchain.ecrypto.test;

import java.util.Arrays;

import org.brewchain.core.crypto.BCKey;
import org.brewchain.core.crypto.ECKey;
import org.brewchain.core.crypto.HashUtil;
import org.brewchain.core.crypto.jni.IPPCrypto;
import org.brewchain.core.util.ByteUtil;
import org.brewchain.ecrypto.impl.EncInstance;
import org.fc.brewchain.bcapi.EncAPI;
import org.fc.brewchain.bcapi.KeyPairs;
import org.spongycastle.util.encoders.Hex;

import javassist.bytecode.ByteArray;
import lombok.val;


public class TestIPPCSgin {

	public static void main(String[] args) {
		
		long start=System.currentTimeMillis();
		
		
		try {
			IPPCrypto.loadLibrary();
		} catch (Throwable e) {
			e.printStackTrace();
		}
		
		IPPCrypto crypto = new IPPCrypto();
		
		byte []pk=new byte[32];
		byte []x=new byte[32];
		byte []y=new byte[32];
		
		byte []s=new byte[32];
		byte []a=new byte[32];
		byte []msg = ("hello cwv 2018-06:"+System.currentTimeMillis()).getBytes();
		
		byte []seed = null;
		if(false){//非随机种子
			seed = new byte[8];
//			ByteArray.write32bit((int)System.currentTimeMillis(), seed, 0);
//			ByteArray.write32bit((int)System.nanoTime(), seed, 4);
			ByteArray.write32bit(100, seed, 0);
			ByteArray.write32bit(300, seed, 4);
			System.out.println("Seed="+Hex.toHexString(seed));
		}
		crypto.genKeys(seed,pk, x, y);
		
//		ECKey eckey = ECKey.fromPrivate(seed);
		BCKey bcKey = new BCKey();
		
		EncInstance api  = new EncInstance();
		api.startup();
		
		KeyPairs key = api.genKeys();
		System.out.println(key.getAddress());
		System.out.println(key.getPrikey());
		System.out.println(key.getPubkey());
		
		System.out.println();
		key = api.genKeys();
		System.out.println(key.getAddress());
		System.out.println(key.getPrikey());
		System.out.println(key.getPubkey());

		System.out.println();
		key = api.genKeys();
		System.out.println(key.getAddress());
		System.out.println(key.getPrikey());
		System.out.println(key.getPubkey());

		System.out.println();
		key = api.genKeys();
		System.out.println(key.getAddress());
		System.out.println(key.getPrikey());
		System.out.println(key.getPubkey());
		
		System.exit(0);
		String ta = "435d8540b4c2a1f4ef4f2da36793f638d6c45c8c";
		String tpriv  = "f93a88bcc0f8858f4ffb169acaff1379c24072c32c679be14d727f804fdcc545";
		String tpub = "c0e1a248155dd9de0f65cbfa785917effb4c6ea66b3ac6e247cfd35c33487f50570566ecd74d54e09230b95913b1db70444a8239d31a4d8b91ceb52d380e460f";
		
		System.out.println(Hex.decode(tpub).length);
		byte[] tx = Arrays.copyOfRange(Hex.decode(tpub), 0, 32);
		byte[] ty = Arrays.copyOfRange(Hex.decode(tpub), 32, 64);
		//tsign=304402203452dc6d406f28ddf3d66cbcb7d2305084dcd94cb3edd19535733d7e6c1a296a022076a5bd531a190adca095f35896cf776218cd44a67f3fbd54f74fc116eb9b35cd
		//      3045022100e39107dc849605f5e2a9a81f1b021cc4b7b9eb96fed608fb1db596c9f0b78a52022066e192a7182a3a1ca0cceb067f5c942b74ff45e06d56eaefad26a2b886c5caa8
		System.out.println(Hex.toHexString(api.ecSign(tpriv, "abc".getBytes())));
		System.out.println(api.ecVerify(tpub, "abc".getBytes(), Hex.decode("c0e1a248155dd9de0f65cbfa785917effb4c6ea66b3ac6e247cfd35c33487f50570566ecd74d54e09230b95913b1db70444a8239d31a4d8b91ceb52d380e460f435d8540b4c2a1f4ef4f2da36793f638d6c45c8c253a7f458a83b618d681d3e69a0496653435f603c294f2ed887c0e9e00c31390b1fa6741ada0e8de35c8adea5dcec89520f31b87d867cbda09d87f35102cbd76")));
		bcKey.signMessage(Hex.decode(tpriv), tx, ty, "abc".getBytes(), s, a);
		
		
		System.out.println();
		
		System.out.println("cpriv="+Hex.toHexString(pk));
//		System.out.println("epriv="+Hex.toHexString(eckey.getPrivKeyBytes()));
		System.out.println();
		
		byte[] pubKeyByte = ByteUtil.merge(x,y);
		System.out.println("cpub ="+Hex.toHexString(pubKeyByte));
//		System.out.println("epub ="+Hex.toHexString(eckey.getPubKey()));
		System.out.println();
		
		System.out.println();System.out.println();
		System.out.println("caddr="+ Hex.toHexString(Arrays.copyOfRange(HashUtil.sha256(pubKeyByte), 0, 20)) );
//		System.out.println("eaddr="+Hex.toHexString(eckey.getAddress()));

		
//		val eckey = ECKey.fromPublicOnly(Hex.decode(tpub));
	    System.out.println(
	    		ECKey.verify(
	    				"abc".getBytes()
	    				,Hex.decode("c0e1a248155dd9de0f65cbfa785917effb4c6ea66b3ac6e247cfd35c33487f50570566ecd74d54e09230b95913b1db70444a8239d31a4d8b91ceb52d380e460f435d8540b4c2a1f4ef4f2da36793f638d6c45c8c253a7f458a83b618d681d3e69a0496653435f603c294f2ed887c0e9e00c31390b1fa6741ada0e8de35c8adea5dcec89520f31b87d867cbda09d87f35102cbd76")
	    				,Hex.decode(tpub)
	    				)
    		);
	    
		
		
		System.out.println();System.out.println();System.out.println();
		System.out.println();System.out.println();System.out.println();
		System.out.println();System.out.println();System.out.println();
//		byte []x1=new byte[32];
//		byte []y1=new byte[32];
//
//		if(crypto.fromPrikey(pk, x1, y1)){
//			System.out.println("from prikey okok");
//		}
//		if(crypto.signMessage(pk, x, y, msg, s, a)){
//			System.out.println("Sign OKOK");
//		}
//		
//		if(crypto.verifyMessage(x, y, msg, s, a)){
//			System.out.println("verify OKOK");
//		}
////		for(int i=0;i<10000;i++){
////			crypto.verifyMessage(x, y, msg, s, a);
////		}
//		System.out.println("p="+Hex.toHexString(pk));
//		System.out.println("x="+Hex.toHexString(x));
////		System.out.println("x1="+Hex.encodeHexString(x1));
//		System.out.println("y="+Hex.toHexString(y));
////		System.out.println("y1="+Hex.encodeHexString(y1));
////		System.out.println("s="+Hex.encodeHexString(s));
////		System.out.println("a="+Hex.encodeHexString(a));
//		System.out.println("cost="+(System.currentTimeMillis()-start));

		
	}

}
