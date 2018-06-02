package com.brewchain.crypto.impl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.ServiceProperty;
import org.brewchain.core.crypto.ECKey;
import org.brewchain.core.crypto.HashUtil;
import org.fc.brewchain.bcapi.EncAPI;
import org.fc.brewchain.bcapi.KeyPairs;
import org.spongycastle.util.encoders.Hex;

import com.google.protobuf.Message;

import lombok.extern.slf4j.Slf4j;
import onight.oapi.scala.commons.SessionModules;
import onight.osgi.annotation.NActorProvider;
import onight.tfw.ntrans.api.ActorService;

@NActorProvider
@Instantiate(name = "bc_crypto")
@Provides(specifications = { ActorService.class, EncAPI.class }, strategy = "SINGLETON")
@Slf4j
public class BrewchainCrypto extends SessionModules<Message> implements EncAPI, ActorService {

	@ServiceProperty(name = "name")
	String name = "bc_crypto";

	static {
		System.load("/root/crypto/brewchain-crypto/crypto/libbrewchain-crypto.so");
	}

	public native long createContext();

	public native void destroyContext();

	public native Object[] createAccount(long context);

	public native Object[] recoverAccount(long context, String priKey);

	public native String signTransaction(long context, String priKey, String nonce, String to, String gasPrice,
			String gasLimit, String value, String data);

	public native int verifySignature(long context, byte[] msgHash, byte[] sigData);

	public native Object[] recoverAccountBySign(long context, byte[] msgHash, byte[] sigData);

	public String priKeyToAddress(String priKey) {
		return "";
	}

	public static void main(String[] args) {

		BrewchainCrypto test = new BrewchainCrypto();

		System.out.println("###createAccount###");

		Object[] key = test.createAccount(test.createContext());

		if (key == null || key.length != 3) {
			System.out.println("key=" + key + ",length=" + key != null ? key.length : 0);
			return;
		}

		String strPrikey = key[0].toString();
		String strPubkey = key[1].toString();
		String strAddress = key[2].toString();

		System.out.println("strPrikey=" + strPrikey);
		System.out.println("strPubkey=" + strPubkey);
		System.out.println("strAddres=" + strAddress);

		System.out.println("");
		System.out.println("###signTransaction###");

		String sign = test.signTransaction(test.createContext(), strPrikey, "0",
				"88b0fb7ef6bd133706053ce4ed6074720725335c", "0", "0", "1", "72e037f3f1e61f5f81b2a71db8e9bc77d324694c");

		System.out.println("sign=" + sign);

		System.out.println("");
		System.out.println("###verifySignature###");
		// TODO msgData = SHA256(RLP(tx))
		System.out.println(test.verifySignature(test.createContext(),
				"72e037f3f1e61f5f81b2a71db8e9bc77d324694c".getBytes(), sign.getBytes()));

		System.out.println("");
		System.out.println("###recoverAccount###");

		System.out.println("key1[0]=" + strPrikey);
		Object[] key1 = test.recoverAccount(test.createContext(), strPrikey);
		int i = 0;
		for (Object o : key1) {
			i++;
			System.out.println("key1[" + i + "]=" + o.toString());
		}

		System.out.println("");
		System.out.println("###recoverAccountBySign###");

		Object[] key2 = test.recoverAccountBySign(test.createContext(),
				"72e037f3f1e61f5f81b2a71db8e9bc77d324694c".getBytes(), sign.getBytes());
		int k = 0;
		for (Object o : key2) {
			k++;
			System.out.println("key2[" + k + "]=" + o.toString());
		}

	}

	//
	// private String nextUID(String key) {
	// SecureRandom ran = new SecureRandom(key.getBytes());
	// ECKey eckey = new ECKey(ran);
	// byte[] encby = HashUtil.ripemd160(eckey.getPubKey());
	// BigInteger i = new BigInteger(Hex.toHexString(encby), 16);
	// val id = hexToMapping(i);
	// val mix = BCNodeHelper.mixStr(id, key);
	// mix + SessionIDGenerator.genSum(mix);
	// }

	@Override
	public KeyPairs genKeys() {
		Object[] key = this.createAccount(this.createContext());
		if (key == null || key.length != 3) {
			log.error("key=" + key + ",length=" + key != null ? key.length + "" : "0");
			return null;
		}

		String strPrikey = key[0].toString();
		String strPubkey = key[1].toString();
		String strAddress = key[2].toString();

		String bcuid = "";
		return new KeyPairs(strPubkey, strPrikey, strAddress, bcuid);
	}

	@Override
	public KeyPairs genKeys(String seed) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] ecEncode(String pubKey, byte[] content) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] ecDecode(String priKey, byte[] content) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] ecSign(String priKey, byte[] contentHash) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String ecSignHex(String priKey, byte[] contentHash) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean ecVerify(String pubKey, byte[] contentHash, byte[] sign) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String ecSignHex(String priKey, String hexHash) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean ecVerifyHex(String pubKey, String hexHash, String signhex) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean ecVerifyHex(String pubKey, byte[] hexHash, String signhex) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String base64Enc(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] base64Dec(String data) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String hexEnc(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] hexDec(String data) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] ecToAddress(byte[] contentHash, String signBase64) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] ecToKeyBytes(byte[] contentHash, String signBase64) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] sha3Encode(byte[] input) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] sha256Encode(byte[] input) {
		// TODO Auto-generated method stub
		return null;
	}
}
