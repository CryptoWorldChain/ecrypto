package org.brewchain.ecrypto.test;

import org.brewchain.core.crypto.HashUtil;

public class HashTest {

	public static void main(String[] args) {
		long start=System.currentTimeMillis();
		byte bb[]="hello".getBytes();
		for(int i=0;i<1000000;i++)
		{
			HashUtil.sha3(bb);
		}
		long end=System.currentTimeMillis();
		System.out.println("cost="+(end-start));
	}

}
