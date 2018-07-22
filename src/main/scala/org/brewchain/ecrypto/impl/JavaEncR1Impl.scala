package org.brewchain.ecrypto.impl

import java.security.SecureRandom

import org.brewchain.core.crypto.ECKey
import org.brewchain.core.crypto.HashUtil
import org.brewchain.core.crypto.jce.ECKeyFactory
import org.brewchain.core.crypto.jce.ECSignatureFactory
import org.fc.brewchain.bcapi.KeyPairs
import org.fc.brewchain.bcapi.crypto.BitMap
import onight.oapi.scala.traits.OLog
import java.io.IOException
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import org.bouncycastle.jce.ECNamedCurveTable
import java.security.interfaces.ECPublicKey
import java.util.Random
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.util.Arrays
import java.math.BigInteger
import org.bouncycastle.crypto.prng.FixedSecureRandom
import org.brewchain.core.util.EndianHelper
import java.security.Signature
import java.security.KeyFactory
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import java.security.interfaces.ECPrivateKey
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.ECKeyParameters
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.jce.ECPointUtil
import org.brewchain.core.util.ByteUtil
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import java.security.spec.ECPoint
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECCurve

/**
 * brew
 *
 * secp256k1
 */
case class JavaEncR1Instance() extends OLog with BitMap with EncTrait {
  Security.addProvider(new BouncyCastleProvider());
  val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
  def genKeys(): KeyPairs = {
    val keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
    keyGen.initialize(ecSpec, new SecureRandom());
    val eckey = keyGen.generateKeyPair();
    val pri = eckey.getPrivate().asInstanceOf[BCECPrivateKey];
    val pub = eckey.getPublic().asInstanceOf[BCECPublicKey];
    val pubkey = hexEnc(EndianHelper.revert(pub.getW.getAffineX.toByteArray())).substring(0, 64) +
      hexEnc(EndianHelper.revert(pub.getW.getAffineY.toByteArray())).substring(0, 64);
    val address = hexEnc(Arrays.copyOfRange(sha256Encode(Hex.decode(pubkey)), 0, 20));
    val prikey = hexEnc(EndianHelper.revert(pri.getS.toByteArray())).substring(0, 64);
    val kp = new KeyPairs(
      pubkey,
      prikey,
      address,
      nextUID(pubkey));
    return kp;
  };
  def genKeys(seed: String): KeyPairs = {
    val keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
    if (seed.getBytes.length != 64) {
      val bytes = new Array[Byte](32);
      val hash = HashUtil.sha256(seed.getBytes);
      new Random(new BigInteger(hash).longValue()).nextBytes(bytes);
      keyGen.initialize(ecSpec, new FixedSecureRandom(bytes));
    } else {
      keyGen.initialize(ecSpec, new FixedSecureRandom(Hex.decode(seed.getBytes)));
    }
    val eckey = keyGen.generateKeyPair();
    val pri = eckey.getPrivate().asInstanceOf[BCECPrivateKey];
    val pub = eckey.getPublic().asInstanceOf[BCECPublicKey];

    //    val ecpoint = ecSpec.getCurve().createPoint(pub.getQ.getAffineXCoord.toBigInteger(),
    //      pub.getQ.getAffineYCoord.toBigInteger());

    //    println("ecpoint=" + ecpoint)

    val pubkey = hexEnc(EndianHelper.revert(pub.getQ.getAffineXCoord.toBigInteger().toByteArray())).substring(0, 64) +
      hexEnc(EndianHelper.revert(pub.getQ.getAffineYCoord.toBigInteger().toByteArray())).substring(0, 64);

    //    val javaKey_x = EndianHelper.revert(Hex.decode(pubkey.substring(0, 64)))
    //    val javaKey_y = EndianHelper.revert(Hex.decode(pubkey.substring(64, 128)))
    //
    //    val ecpoint2 = ecSpec.getCurve().createPoint(new BigInteger(hexEnc(javaKey_x),16), new BigInteger(hexEnc(javaKey_y),16));
    //    
    //    println("ecpoint2=" + ecpoint2)

    val address = hexEnc(Arrays.copyOfRange(sha256Encode(Hex.decode(pubkey)), 0, 20));

    //    println("pubkeyencode="+hexEnc(pub.getQ().toBigInteger().toByteArray()))
    val prikey = hexEnc(EndianHelper.revert(pri.getS.toByteArray())).substring(0, 64);
    val kp = new KeyPairs(
      pubkey,
      prikey, address,
      nextUID(pubkey));
    return kp;
  };

  def ecSign(priKeyStr: String, contentHash: Array[Byte]): Array[Byte] = {
//    println("content=hash="+hexEnc(contentHash));
    val javaKey = hexEnc(EndianHelper.revert(Hex.decode(priKeyStr)))
    val priS = new BigInteger(javaKey, 16);
    val privKeySpec = new ECPrivateKeySpec(priS, ecSpec);
    val kf = KeyFactory.getInstance("ECDSA","BC");
    val prikey = kf.generatePrivate(privKeySpec).asInstanceOf[BCECPrivateKey];
    val prikey_restore = hexEnc(EndianHelper.revert(prikey.getS.toByteArray())).substring(0, 64);
    val param = prikey.getParameters; //new ECParameterSpec();

    val Q = ecSpec.getG().multiply(prikey.getD());

    val pubSpec = new ECPublicKeySpec(Q, ecSpec);
    val pub = kf.generatePublic(pubSpec).asInstanceOf[BCECPublicKey];
//        val pubkey = hexEnc(EndianHelper.revert(pub.getW.getAffineX.toByteArray())).substring(0, 64) +
//          hexEnc(EndianHelper.revert(pub.getW.getAffineY.toByteArray())).substring(0, 64);
//         println("regen.pubkey="+pubkey)
    val ecdsaSigner = new ECDSASigner();
    ecdsaSigner.init(true, new ECPrivateKeyParameters(prikey.getD,
      new ECDomainParameters(param.getCurve, param.getG, param.getN)));
    val sig = ecdsaSigner.generateSignature(EndianHelper.revert(contentHash));
    val s = EndianHelper.revert(sig(0).toByteArray())
    val a = EndianHelper.revert(sig(1).toByteArray())
//    val ds = EndianHelper.revert(hexDec(s))
//    val da = EndianHelper.revert(hexDec(a))
//    println("ds=" + hexEnc(s).substring(0,64));
//    println("da=" + hexEnc(a).substring(0,64));
    val rand20bytes = new Array[Byte](20);
    {
      val hash = HashUtil.sha256(s);
      new Random(new BigInteger(hash).longValue()).nextBytes(rand20bytes);
    }
    ByteUtil.merge(
      hexDec(hexEnc(EndianHelper.revert(pub.getW.getAffineX.toByteArray())).substring(0, 64)),
      hexDec(hexEnc(EndianHelper.revert(pub.getW.getAffineY.toByteArray())).substring(0, 64)),rand20bytes, 
      hexDec(hexEnc(s).substring(0,64)), 
      hexDec(hexEnc(a).substring(0,64)));
  }

  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    try {
      //      val eckey = ECKey.fromPublicOnly(Hex.decode(pubKey));
      //      eckey.verify(contentHash, sign);
//      println("content=hash="+hexEnc(contentHash));
      val strsign = hexEnc(sign);
      val javaKey_x = EndianHelper.revert(Hex.decode(strsign.substring(0, 64)))
      val javaKey_y = EndianHelper.revert(Hex.decode(strsign.substring(64, 128)))
//      val s = Arrays.copyOfRange(sign, 84, 116);
//      val a = Arrays.copyOfRange(sign, 116, 148);

//      println("encpub.x=" + hexEnc(javaKey_x))
//      println("encpub.y=" + hexEnc(javaKey_y))
      //      val x = Arrays.copyOfRange(pubKeyBytes, 0, 32);
//      val y = Arrays.copyOfRange(pubKeyBytes, 32, 64);
//      val s = Arrays.copyOfRange(sign, 84, 116);
//      val a = Arrays.copyOfRange(sign, 116, 148);

      //      val pubpoint=new ECPoint(new BigInteger(javaKey_x),new BigInteger(javaKey_y));
      val r_byte = new Array[Byte](32);
      val s_byte = new Array[Byte](32);
      System.arraycopy(sign, 84, r_byte, 0, 32)
      System.arraycopy(sign, 116, s_byte, 0, 32)
      val r = EndianHelper.revert(r_byte)
      val s = EndianHelper.revert(s_byte)

      val kf = KeyFactory.getInstance("ECDSA", "BC");
      val params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());
      val ecpoint = ecSpec.getCurve().createPoint(new BigInteger(hexEnc(javaKey_x), 16), new BigInteger(hexEnc(javaKey_y), 16));
      //      val point = ECPointUtil.decodePoint(params.getCurve(), ByteUtil.merge(javaKey_x,javaKey_y));
      val pubkeySpec = new ECPublicKeySpec(ecpoint, new ECParameterSpec(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN()));
      val ecdsaSigner = new ECDSASigner();
      ecdsaSigner.init(false, new ECPublicKeyParameters(pubkeySpec.getQ,
        new ECDomainParameters(ecSpec.getCurve, ecSpec.getG, ecSpec.getN)));
      val vresult = ecdsaSigner.verifySignature(EndianHelper.revert(contentHash), 
          new BigInteger(hexEnc(r), 16), 
          new BigInteger(hexEnc(s), 16))
      vresult
    } catch {
      case e: IOException =>
        e.printStackTrace();
        false;
      case e: Exception =>
        e.printStackTrace();
        false;
      case e: Throwable =>
        e.printStackTrace();
        false;
    }
  }

  def ecToAddress(contentHash: Array[Byte], sign: String): Array[Byte] = {
    ECKey.signatureToAddress(contentHash, sign);
  }

  def ecToKeyBytes(contentHash: Array[Byte], sign: String): Array[Byte] = {
    ECKey.signatureToKeyBytes(contentHash, sign);
  }

  def priKeyToKey(privKey: String): KeyPairs = {
    val eckey = ECKey.fromPrivate(hexDec(privKey));
    val pubstr = Hex.toHexString(eckey.getPubKey);
    val kp = new KeyPairs(
      hexEnc(eckey.getPubKey),
      hexEnc(eckey.getPrivKeyBytes),
      hexEnc(eckey.getAddress),
      nextUID(pubstr));
    return kp;
  }

  def sha3Encode(content: Array[Byte]): Array[Byte] = {
    HashUtil.sha3(content);
  }
  def sha256Encode(content: Array[Byte]): Array[Byte] = {
    HashUtil.sha256(content);
  }

}