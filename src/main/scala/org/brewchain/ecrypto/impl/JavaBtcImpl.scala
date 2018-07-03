package org.brewchain.ecrypto.impl

import java.security.SecureRandom

import org.brewchain.core.crypto.HashUtil
import org.brewchain.core.crypto.jce.ECKeyFactory
import org.brewchain.core.crypto.jce.ECSignatureFactory
import org.brewchain.core.crypto.jce.SpongyCastleProvider
import org.fc.brewchain.bcapi.KeyPairs
import org.fc.brewchain.bcapi.crypto.BitMap
import org.spongycastle.jce.spec.ECPrivateKeySpec
import org.spongycastle.util.encoders.Hex

import onight.oapi.scala.traits.OLog
import org.brewchain.ecrypto.address.btc.BTCKey

case class JavaBtcInstance() extends OLog with BitMap with EncTrait {
  def genKeys(): KeyPairs = {
    val ran = new SecureRandom();
    //ran.generateSeed(System.currentTimeMillis().asInstanceOf[Int])
    val eckey = new BTCKey(ran);
    val pubstr = Hex.toHexString(eckey.getPubKey);
    val kp = new KeyPairs(
      hexEnc(eckey.getPubKey),
      hexEnc(eckey.getPrivKeyBytes),
//      hexEnc(eckey.getAddress),
      "",
      nextUID(pubstr));
    return kp;
  };
  def genKeys(seed: String): KeyPairs = {
    val eckey = BTCKey.fromPrivate(HashUtil.sha3(seed.getBytes()))
    val pubstr = Hex.toHexString(eckey.getPubKey);
    val kp = new KeyPairs(
      hexEnc(eckey.getPubKey),
      Hex.toHexString(eckey.getPrivKeyBytes),
//      Hex.toHexString(eckey.getAddress),
      "",
      nextUID(pubstr));
    return kp
  };

  def ecSign(priKey: String, contentHash: Array[Byte]): Array[Byte] = {
//    val eckey = BTCKey.fromPrivate(Hex.decode(priKey));
//    val ecSig = ECSignatureFactory.getRawInstance(SpongyCastleProvider.getInstance());
//    val prikey = ECKeyFactory
//      .getInstance(SpongyCastleProvider.getInstance())
//      .generatePrivate(new ECPrivateKeySpec(eckey.getPrivKey, BTCKey.CURVE_SPEC));
//    ecSig.initSign(prikey);
//    ecSig.update(contentHash);
//    ecSig.sign();
    null
  }

  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    val eckey = BTCKey.fromPublicOnly(Hex.decode(pubKey));
    eckey.verify(contentHash, sign);
  }

  def sha3Encode(content: Array[Byte]): Array[Byte] = {
    HashUtil.sha3(content);
  }
  def sha256Encode(content: Array[Byte]): Array[Byte] = {
    HashUtil.sha256(content);
  }

  def ecToKeyBytes(pubKey: String, content: String): String = {
//    val key = BTCKey.fromPublicOnly(pubKey.getBytes);
//    val contentHash = HashUtil.sha256(content.getBytes);
//    val sig = key.doSign(contentHash);
//    hexEnc(BTCKey.signatureToKeyBytes(contentHash, sig));
    null
  }

}