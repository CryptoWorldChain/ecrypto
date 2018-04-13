package org.brewchain.ecrypto.enc;

import org.brewchain.core.crypto.HashUtil;
import org.brewchain.ecrypto.impl.EncInstance;
import org.fc.brewchain.bcapi.KeyPairs;

import lombok.val;

public class EncAPITest {

	public static void main(String[] args) {
		
		
		EncInstance enc = new EncInstance();
		KeyPairs key = enc.genKeys();
		
		System.out.println("bcuid:" + key.getBcuid());
		System.out.println("pri:  " + key.getPrikey());
		System.out.println("pub:  " + key.getPubkey());
		System.out.println("addr: " + key.getAddress());
	    String content = "测试";
	    byte[] hash = HashUtil.sha3(content.getBytes());
	    System.out.println("hash: " + hash);
	    val sign = enc.ecSignHex(key.getPrikey(), hash);
	    System.out.println("sign: " + sign);
	    
	    System.out.println(enc.ecToAddress(hash, sign));
	    System.out.println(enc.ecToAddress(key.getPubkey(), content));

	    System.out.println(enc.ecToKeyBytes(hash, sign));
	    System.out.println(enc.ecToKeyBytes(key.getPubkey(), content));
		
	    
//	    enc.ecVerify(pubKey, content, r, s, v);
	}
}
