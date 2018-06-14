package org.brewchain.core.crypto;

import static org.brewchain.core.util.ByteUtil.bigIntegerToBytes;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;

import org.brewchain.core.crypto.jce.ECKeyPairGenerator;
import org.brewchain.core.crypto.jce.SpongyCastleProvider;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.prng.FixedSecureRandom;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.util.encoders.Hex;

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
	
	public KeyPair getKeys(byte[] seed) {
		SecureRandom secureRandom = new FixedSecureRandom(Hex.decode("seed"));
		final KeyPairGenerator keyPairGen = ECKeyPairGenerator.getInstance(SpongyCastleProvider.getInstance(), secureRandom);
	    final KeyPair keyPair = keyPairGen.generateKeyPair();
	    PrivateKey privKey = keyPair.getPrivate();
	    
	    byte[] privKeyBytes;
	    if (privKey instanceof BCECPrivateKey) {
	    		privKeyBytes = bigIntegerToBytes(((BCECPrivateKey) privKey).getD(), 32);
	    		
	    		System.out.println(Hex.toHexString(privKeyBytes));
        } else {
        		privKeyBytes = null;
        }
	    
	    return null;
	}
	 
}
