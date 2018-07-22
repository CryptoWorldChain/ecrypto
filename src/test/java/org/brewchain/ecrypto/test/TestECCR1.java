package org.brewchain.ecrypto.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class TestECCR1 {
	private static class FixedRand extends SecureRandom {
		MessageDigest sha;
		byte[] state;

		FixedRand() {
			try {
				this.sha = MessageDigest.getInstance("SHA-1");
				this.state = sha.digest();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("can't find SHA-1!");
			}
		}

		public void nextBytes(byte[] bytes) {
			int off = 0;

			sha.update(state);

			while (off < bytes.length) {
				state = sha.digest();

				if (bytes.length - off > state.length) {
					System.arraycopy(state, 0, bytes, off, state.length);
				} else {
					System.arraycopy(state, 0, bytes, off, bytes.length - off);
				}

				off += state.length;

				sha.update(state);
			}
		}
	}

	/**
	 * Return a SecureRandom which produces the same value. <b>This is for
	 * testing only!</b>
	 * 
	 * @return a fixed random
	 */
	public static SecureRandom createFixedRandom() {
		return new FixedRand();
	}

	public static void main(String[] args) {

		try {
			Security.addProvider(new BouncyCastleProvider());

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC","BC");
			ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
			// byte
			// bb[]=Hex.decodeHex("000082452dc26567842e92b515d42df71e7690604af3e40b5807810be81c6b95".toCharArray());
			// keyGen.initialize(ecSpec, new FixedSecureRandom(bb));
			keyGen.initialize(ecSpec, new SecureRandom());

			KeyPair keyPair = keyGen.generateKeyPair();
			Signature signature = Signature.getInstance("ECDSA", "BC");

			// generate a signature
			BCECPrivateKey pri = (BCECPrivateKey) keyPair.getPrivate();
			pri = (BCECPrivateKey) keyPair.getPrivate();
			System.out.println("pri.s=" + pri.getS().toString(16));
			System.out.println("pri.p=" + Hex.encodeHexString(pri.getEncoded()));

			// ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1",
			// ecSpec.getCurve(), ecSpec.getG(),
			// ecSpec.getN());
//			ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(pri.getS(), ecSpec);
//			KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());

//			ECPrivateKey pri2 = (ECPrivateKey) kf.generatePrivate(privKeySpec);
			ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
//			System.out.println("pri=" + pri2.getS().toString(16));
			System.out.println("pri.A=" + pri.getParams().getCurve().getA().toString(16));
			System.out.println("pri.B=" + pri.getParams().getCurve().getB().toString(16));
			System.out.println("pub.X=" + pub.getW().getAffineX().toString(16) + ",Y="
					+ pub.getW().getAffineY().toString(16));
			signature.initSign(keyPair.getPrivate(), TestECCR1.createFixedRandom());

			byte[] message = new byte[] { (byte) 'a', (byte) 'b', (byte) 'c' };

			signature.update(message);

			byte[] sigBytes = signature.sign();

			// verify a signature

			signature.initVerify(keyPair.getPublic());

			signature.update(message);

			if (signature.verify(sigBytes)) {
				System.out.println("signature verification succeeded.");
			} else {
				System.out.println("signature verification failed.");
			}

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}

}
