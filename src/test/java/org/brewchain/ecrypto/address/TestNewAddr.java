package org.brewchain.ecrypto.address;

import java.util.List;

import org.brewchain.ecrypto.address.AddressFactory;
import org.brewchain.ecrypto.address.NewAddress;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TestNewAddr {

	public static String randomPK(int length) {
	    //随机字符串的随机字符库
	    String KeyString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
	    StringBuffer sb = new StringBuffer();
	    int len = KeyString.length();
	    for (int i = 0; i < length; i++) {
	       sb.append(KeyString.charAt((int) Math.round(Math.random() * (len - 1))));
	    }
	    return sb.toString();
	}
	
	public static void main(String[] args) throws Exception {

		String private_key = randomPK(81);
		
		org.brewchain.ecrypto.address.NewAddress newAddr = org.brewchain.ecrypto.address.AddressFactory.create(org.brewchain.ecrypto.address.AddressFactory.Mode.IOTA);
		
		log.info("pri="+private_key);
		List<String> addr = newAddr.getNewAddress(private_key, 2, 0, false, 1, true);
		for(int i=0;i<addr.size();i++) {
			log.info("addr.get("+i+")="+addr.get(i));
		}
		
		//  TODO seed相同，相同顺序的地址也相同
		log.info("");
		log.info("pri="+private_key);
		private_key = "NDIICQCKUMCBXUGTIUZCCTYRMYVISHFGVEJDLVDODS9TELXS9YGSNSXDJTNTZUZJOJNBTYLPGIFUXVHKH";
		addr = newAddr.getNewAddress(private_key, 2, 0, false, 5, true);
		for(int i=0;i<addr.size();i++) {
			log.info("addr.get("+i+")="+addr.get(i));
		}
		

		log.info("");
		log.info("pri="+private_key);
		private_key = "NDIICQCKUMCBXUGTIUZCCTYRMYVISHFGVEJDLVDODS9TELXS9YGSNSXDJTNTZUZJOJNBTYLPGIFUXVHKH";
		addr = newAddr.getNewAddress(private_key, 2, 4, false, 1, true);
		for(int i=0;i<addr.size();i++) {
			log.info("addr.get("+i+")="+addr.get(i));
		}
	}
}
