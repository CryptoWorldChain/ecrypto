package org.brewchain.ecrypto.impl

import java.security.SecureRandom
import java.util.Arrays

import scala.beans.BeanProperty

import org.apache.commons.codec.binary.Base64
import org.apache.felix.ipojo.annotations.Instantiate
import org.apache.felix.ipojo.annotations.Provides
import org.apache.felix.ipojo.annotations.ServiceProperty
import org.brewchain.core.crypto.ECIESCoder
import org.brewchain.core.crypto.ECKey
import org.brewchain.core.crypto.HashUtil
import org.brewchain.core.crypto.jce.ECKeyFactory
import org.brewchain.core.crypto.jce.ECSignatureFactory
import org.brewchain.core.crypto.jce.SpongyCastleProvider
import org.brewchain.core.crypto.jni.IPPCrypto
import org.brewchain.core.util.ByteUtil
import org.fc.brewchain.bcapi.EncAPI
import org.fc.brewchain.bcapi.KeyPairs
import org.fc.brewchain.bcapi.crypto.BCNodeHelper
import org.fc.brewchain.bcapi.crypto.BitMap
import org.spongycastle.jce.spec.ECPrivateKeySpec
import org.spongycastle.util.encoders.Hex

import com.google.protobuf.Message

import onight.oapi.scala.commons.PBUtils
import onight.oapi.scala.commons.SessionModules
import onight.oapi.scala.traits.OLog
import onight.osgi.annotation.NActorProvider
import onight.tfw.ntrans.api.ActorService
import onight.tfw.outils.serialize.SessionIDGenerator

import org.brewchain.ecrypto.address.AddressFactory
import org.brewchain.ecrypto.address.AddressEnum;
import java.util.List

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
        null;
      }
    } else {
      null;
    }
  }

  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    val pubKeyBytes = Hex.decode(pubKey);
    val x = Arrays.copyOfRange(pubKeyBytes, 0, 32);
    val y = Arrays.copyOfRange(pubKeyBytes, 32, 64);
    val s = Arrays.copyOfRange(sign, 84, 116);
    val a = Arrays.copyOfRange(sign, 116, 148);
    crypto.verifyMessage(x, y, contentHash, s, a);
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

  def ecToKeyBytes(pubKey: String, content: String): String = {
    val key = ECKey.fromPublicOnly(pubKey.getBytes);
    val contentHash = sha256Encode(content.getBytes);
    val sig = key.doSign(contentHash);
    hexEnc(ECKey.signatureToKeyBytes(contentHash, sig));
  }

}