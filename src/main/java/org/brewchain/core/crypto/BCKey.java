package org.brewchain.core.crypto;

import static org.brewchain.core.util.ByteUtil.bigIntegerToBytes;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.brewchain.core.crypto.jce.ECKeyFactory;
import org.brewchain.core.crypto.jce.ECSignatureFactory;
import org.brewchain.core.crypto.jce.SpongyCastleProvider;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.prng.FixedSecureRandom;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import lombok.val;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class BCKey implements Serializable {

	private static final long serialVersionUID = -728224901792295832L;
	
	
	public static final ECDomainParameters CURVE;
    public static final ECParameterSpec CURVE_SPEC;
    public static final BigInteger HALF_CURVE_ORDER;
    private static final SecureRandom secureRandom;
    
	static {
		
		// Brewchain uses secp256r1.
		X9ECParameters params = SECNamedCurves.getByName("secp256r1");
		CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
		CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH());
		HALF_CURVE_ORDER = params.getN().shiftRight(1);
		secureRandom = new SecureRandom();
		
	}
	
	
	private KeyPairGenerator keyPairGen;
	public BCKey() {
//		this(secureRandom);
	}
//	public BCKey(SecureRandom secureRandom) {
//		keyPairGen = ECKeyPairGenerator.getInstance(SpongyCastleProvider.getInstance(), secureRandom);
//	}
//	public BCKey(Provider provider, SecureRandom secureRandom) {
//		keyPairGen = ECKeyPairGenerator.getInstance(provider, secureRandom);
//	}
	
	public void genKeys(byte[] seed, byte[] privKeyBytes, byte[] x, byte[] y) {
		if(seed != null && seed.length > 0) {
			keyPairGen = org.brewchain.core.crypto.jce.ECKeyPairGenerator.getInstance(SpongyCastleProvider.getInstance(), new FixedSecureRandom(seed));
		}else {
			keyPairGen = org.brewchain.core.crypto.jce.ECKeyPairGenerator.getInstance(SpongyCastleProvider.getInstance(), secureRandom);
		}
	    KeyPair keyPair = keyPairGen.generateKeyPair();
	    
	    if (keyPair.getPrivate() instanceof BCECPrivateKey) {
	    		privKeyBytes = bigIntegerToBytes(((BCECPrivateKey) keyPair.getPrivate()).getD(), 32);
//	    		System.out.println("jpriv="+Hex.toHexString(privKeyBytes));
        } else {
        		privKeyBytes = null;
        }
	    
	    if (keyPair.getPublic() instanceof ECPublicKey) {
	        	final java.security.spec.ECPoint publicPointW = ((ECPublicKey) keyPair.getPublic()).getW();
	    		final BigInteger xCoord = publicPointW.getAffineX();
	    		final BigInteger yCoord = publicPointW.getAffineY();
//	    		org.spongycastle.math.ec.ECPoint point = 
	    				CURVE.getCurve().createPoint(xCoord, yCoord);
	    		
	    		x = bigIntegerToBytes(xCoord);
	    		y = bigIntegerToBytes(yCoord);
	    		
//	    		byte[] pubKeyBytes=ByteUtil.merge(x,y);
//	    		System.out.println("jpub ="+Hex.toHexString(pubKeyBytes));
//	    		
//	    		byte[] addr = Arrays.copyOfRange(HashUtil.sha256(pubKeyBytes),0,20);
//	    		System.out.println("jaddr="+Hex.toHexString(addr));
		}
	}
	
	public boolean fromPrikey(byte[] privKeyBytes, byte[] x, byte[] y) {
		BigInteger priv = new BigInteger(1, privKeyBytes);
//		PrivateKey privKey = ECKeyFactory.getInstance(SpongyCastleProvider.getInstance()).generatePrivate(new ECPrivateKeySpec(priv, CURVE_SPEC));
		ECPoint pub = CURVE.getG().multiply(priv);
		if(pub != null && pub.getXCoord() != null && pub.getYCoord() != null) {
			x = pub.getAffineXCoord().getEncoded();
			y = pub.getAffineYCoord().getEncoded();
			CURVE.getCurve().createPoint(pub.getXCoord().toBigInteger(), pub.getYCoord().toBigInteger());
			return true;
		}
		return false;
	}
	
	public boolean signMessage(byte[] privKeyBytes, byte[] x, byte[] y, byte[] msg, byte[] s, byte[] a) {
		this.fromPrikey(privKeyBytes, x, y);
		
		Signature ecSig = ECSignatureFactory.getRawInstance(SpongyCastleProvider.getInstance());
	    try {
	    		java.security.PrivateKey prikey = ECKeyFactory
			  .getInstance(SpongyCastleProvider.getInstance())
			  .generatePrivate(new ECPrivateKeySpec(new BigInteger(1, privKeyBytes), CURVE_SPEC));
			ecSig.initSign(prikey);
			ecSig.update(msg);
			
			// TODO 
			System.out.println(Hex.toHexString(ecSig.sign()));
			
			
			return true;
		} catch (InvalidKeyException e) {
			return false;
		} catch (InvalidKeySpecException e) {
			return false;
		} catch (SignatureException e) {
			return false;
		} finally {
			
		}
		
		
	}
	
	public boolean verifyMessage(byte[] x, byte[] y, byte[] msg, byte[] s, byte[] a) {
//		val eckey = ECKey.fromPublicOnly(ByteUtil.merge(x,y));
//	    return ECKey.verify(data, signature, ByteUtil.merge(x,y))
		// TODO
		return false;
	}
	 
}
