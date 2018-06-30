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

case class JavaEncInstance() extends OLog with BitMap with EncTrait {
  def genKeys(): KeyPairs = {
    val ran = new SecureRandom();
    //ran.generateSeed(System.currentTimeMillis().asInstanceOf[Int])
    val eckey = new ECKey(ran);
    val pubstr = Hex.toHexString(eckey.getPubKey);
    val kp = new KeyPairs(
      hexEnc(eckey.getPubKey),
      hexEnc(eckey.getPrivKeyBytes),
      hexEnc(eckey.getAddress),
      nextUID(pubstr));
    return kp;
  };
  def genKeys(seed: String): KeyPairs = {
    val eckey = ECKey.fromPrivate(HashUtil.sha3(seed.getBytes()))
    val pubstr = Hex.toHexString(eckey.getPubKey);
    val kp = new KeyPairs(
      hexEnc(eckey.getPubKey),
      Hex.toHexString(eckey.getPrivKeyBytes),
      Hex.toHexString(eckey.getAddress),
      nextUID(pubstr));
    return kp
  };

  def ecSign(priKey: String, contentHash: Array[Byte]): Array[Byte] = {
    val eckey = ECKey.fromPrivate(Hex.decode(priKey));
    val ecSig = ECSignatureFactory.getRawInstance(SpongyCastleProvider.getInstance());
    val prikey = ECKeyFactory
      .getInstance(SpongyCastleProvider.getInstance())
      .generatePrivate(new ECPrivateKeySpec(eckey.getPrivKey, ECKey.CURVE_SPEC));
    ecSig.initSign(prikey);
    ecSig.update(contentHash);
    ecSig.sign();
  }

  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    val eckey = ECKey.fromPublicOnly(Hex.decode(pubKey));
    eckey.verify(contentHash, sign);
  }

  def sha3Encode(content: Array[Byte]): Array[Byte] = {
    HashUtil.sha3(content);
  }
  def sha256Encode(content: Array[Byte]): Array[Byte] = {
    HashUtil.sha256(content);
  }

  def ecToKeyBytes(pubKey: String, content: String): String = {
    val key = ECKey.fromPublicOnly(pubKey.getBytes);
    val contentHash = HashUtil.sha256(content.getBytes);
    val sig = key.doSign(contentHash);
    hexEnc(ECKey.signatureToKeyBytes(contentHash, sig));
  }

}