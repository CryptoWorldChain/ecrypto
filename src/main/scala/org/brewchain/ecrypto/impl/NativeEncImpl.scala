package org.brewchain.ecrypto.impl

import java.util.Arrays

import org.brewchain.core.crypto.jni.IPPCrypto
import org.brewchain.core.util.ByteUtil
import org.fc.brewchain.bcapi.KeyPairs
import org.spongycastle.util.encoders.Hex

import onight.oapi.scala.traits.OLog
import org.brewchain.ecrypto.impl.JavaEncInstance

case class NativeEncInstance(crypto: IPPCrypto) extends OLog with EncTrait {
  def genKeys(): KeyPairs = {
    val pk = new Array[Byte](32);
    val x = new Array[Byte](32);
    val y = new Array[Byte](32);
    crypto.genKeys(null, pk, x, y);
    val pubKeyByte = ByteUtil.merge(x, y);
    val privKey = hexEnc(pk);
    val pubKey = hexEnc(pubKeyByte);
    val address = hexEnc(Arrays.copyOfRange(sha256Encode(pubKeyByte), 0, 20));
    val kp = new KeyPairs(
      pubKey,
      privKey,
      address,
      nextUID(pubKey));
    kp;
  };
  def genKeys(seed: String): KeyPairs = {
    val pk = new Array[Byte](32);
    val x = new Array[Byte](32);
    val y = new Array[Byte](32);
    crypto.genKeys(sha3Encode(seed.getBytes()), pk, x, y);
    val pubKeyByte = ByteUtil.merge(x, y);
    val privKey = hexEnc(pk);
    val pubKey = hexEnc(pubKeyByte);
    val address = hexEnc(Arrays.copyOfRange(sha256Encode(pubKeyByte), 0, 20));
    val kp = new KeyPairs(
      pubKey,
      privKey,
      address,
      nextUID(pubKey));
    kp;
  };

  def ecSign(priKey: String, contentHash: Array[Byte]): Array[Byte] = {
    val privKeyBytes: Array[Byte] = Hex.decode(priKey);
    val x = new Array[Byte](32);
    val y = new Array[Byte](32);
    if (crypto.fromPrikey(privKeyBytes, x, y)) {
      val s = new Array[Byte](32);
      val a = new Array[Byte](32);
      if (crypto.signMessage(privKeyBytes, x, y, contentHash, s, a)) {
        val signBytes = ByteUtil.merge(x, y, Arrays.copyOfRange(sha256Encode(ByteUtil.merge(x, y)), 0, 20), s, a);
        signBytes;
      } else {
        var enc: EncTrait = JavaEncInstance();
        enc.ecSign(priKey, contentHash);
      }
    } else {
      var enc: EncTrait = JavaEncInstance();
      enc.ecSign(priKey, contentHash);
    }
  }

  //  def ecToKeyBytes(pubKey: String, content: String): String = {
  //    val key = ECKey.fromPublicOnly(pubKey.getBytes);
  //    val contentHash = HashUtil.sha256(content.getBytes);
  //    val sig = key.doSign(contentHash);
  //    hexEnc(ECKey.signatureToKeyBytes(contentHash, sig));
  //  }

  def ecToAddress(contentHash: Array[Byte], sign: String): Array[Byte] = {
    val signBytes: Array[Byte] = hexDec(sign);
    Arrays.copyOfRange(signBytes, 64, 84);
  }

  def ecToKeyBytes(contentHash: Array[Byte], sign: String): Array[Byte] = {
    val signBytes: Array[Byte] = hexDec(sign);
    Arrays.copyOfRange(signBytes, 0, 64);
  }

  def priKeyToKey(privKey: String): KeyPairs = {
    val privKeyBytes: Array[Byte] = Hex.decode(privKey);
    val x = new Array[Byte](32);
    val y = new Array[Byte](32);
    if (crypto.fromPrikey(privKeyBytes, x, y)) {
      val pubKeyByte = ByteUtil.merge(x, y);
      val pubKey = hexEnc(pubKeyByte);
      val address = hexEnc(Arrays.copyOfRange(sha256Encode(pubKeyByte), 0, 20));
      val kp = new KeyPairs(
        pubKey,
        privKey,
        address,
        nextUID(pubKey));
      kp;
    } else {
      null;
    }
  }
  val javaEnc: JavaEncInstance = JavaEncInstance();
  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    if (pubKey.length() == 128 && sign.length == 148) {
      val pubKeyBytes = Hex.decode(pubKey);
      val x = Arrays.copyOfRange(pubKeyBytes, 0, 32);
      val y = Arrays.copyOfRange(pubKeyBytes, 32, 64);
      val s = Arrays.copyOfRange(sign, 84, 116);
      val a = Arrays.copyOfRange(sign, 116, 148);
      if (crypto.verifyMessage(x, y, contentHash, s, a)) {
        true;
      } else {
        javaEnc.ecVerify(pubKey, contentHash, sign);
      }
    } else {
      javaEnc.ecVerify(pubKey, contentHash, sign);
    }
  }

  def sha3Encode(content: Array[Byte]): Array[Byte] = {
    val ret = new Array[Byte](32);
    crypto.bsha3(content, ret);
    ret;
  }
  def sha256Encode(content: Array[Byte]): Array[Byte] = {
    val ret = new Array[Byte](32);
    crypto.bsha256(content, ret);
    ret;
  }

}