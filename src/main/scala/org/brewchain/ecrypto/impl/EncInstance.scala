package org.brewchain.ecrypto.impl

import onight.osgi.annotation.NActorProvider
import org.apache.felix.ipojo.annotations.Instantiate
import onight.tfw.ntrans.api.ActorService
import org.fc.brewchain.bcapi.EncAPI
import org.apache.felix.ipojo.annotations.Provides
import onight.oapi.scala.commons.SessionModules
import onight.oapi.scala.commons.PBUtils
import onight.oapi.scala.traits.OLog
import com.google.protobuf.Message
import org.apache.felix.ipojo.annotations.ServiceProperty
import scala.beans.BeanProperty
import org.fc.brewchain.bcapi.KeyPairs
import org.brewchain.core.crypto.ECKey
import org.spongycastle.util.encoders.Hex
import java.security.SecureRandom
import org.brewchain.core.crypto.ECIESCoder
import org.brewchain.core.crypto.jce.ECSignatureFactory
import org.brewchain.core.crypto.jce.SpongyCastleProvider
import org.brewchain.core.crypto.jce.ECKeyFactory
import org.spongycastle.jce.spec.ECPrivateKeySpec
import org.apache.commons.codec.binary.Base64
import org.brewchain.core.crypto.HashUtil
import onight.tfw.outils.serialize.SessionIDGenerator
import org.fc.brewchain.bcapi.crypto.BitMap
import org.fc.brewchain.bcapi.crypto.BCNodeHelper
import org.osgi.framework.BundleContext
import org.brewchain.core.crypto.ECKey.ECDSASignature
import org.brewchain.core.crypto.HashUtil;

@NActorProvider
@Instantiate(name = "bc_encoder")
@Provides(specifications = Array(classOf[ActorService], classOf[EncAPI]), strategy = "SINGLETON")
class EncInstance extends SessionModules[Message] with BitMap with PBUtils with OLog with EncAPI with ActorService {

  @ServiceProperty(name = "name")
  @BeanProperty
  var name: String = "bc_encoder";

  def apply(bundleContext: BundleContext): EncInstance = {
    log.debug("apply:bundleContext=" + bundleContext)
    this
  }
  
  def apply(): EncInstance = {
    log.debug("Apply()=" )
    this
  }
  def nextUID(key: String = "BCC2018"): String = {
    //    val id = UUIG.generate()
    val ran = new SecureRandom(key.getBytes);
    //ran.generateSeed(System.currentTimeMillis().asInstanceOf[Int])
    val eckey = new ECKey(ran);
    val encby = HashUtil.ripemd160(eckey.getPubKey);
    //    println("hex=" + Hex.toHexString(encby))
    val i = BigInt(Hex.toHexString(encby),16)
    //    println("i=" + i)
    val id = hexToMapping(i)
    val mix = BCNodeHelper.mixStr(id, key);
    mix + SessionIDGenerator.genSum(mix)
  }

  override def getModule: String = "BIP"
  override def getCmds: Array[String] = Array("ENC");
  def genKeys(): KeyPairs = {
    val ran = new SecureRandom();
    //ran.generateSeed(System.currentTimeMillis().asInstanceOf[Int])
    val eckey = new ECKey(ran);
    val pubstr = Hex.toHexString(eckey.getPubKey);
    val kp = new KeyPairs(
      Hex.toHexString(eckey.getPubKey),
      Hex.toHexString(eckey.getPrivKeyBytes),
      Hex.toHexString(eckey.getAddress),
      nextUID(pubstr));
    return kp
  };

  def ecEncode(pubKey: String, content: Array[Byte]): Array[Byte] = {
    val eckey = ECKey.fromPublicOnly(Hex.decode(pubKey));
    val encBytes = ECIESCoder.encrypt(eckey.getPubKeyPoint, content);
    encBytes
  }
  
  def ecDecode(priKey: String, content: Array[Byte]): Array[Byte] = {
    val eckey = ECKey.fromPrivate(Hex.decode(priKey));
    val orgBytes = ECIESCoder.decrypt(eckey.getPrivKey, content);
    orgBytes;
  }

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

  def ecVerify(priKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    true
  }

  def base64Enc(data: Array[Byte]): String = {
    Base64.encodeBase64String(data);
  }

  def base64Dec(str: String): Array[Byte] = {
    Base64.decodeBase64(str);
  }

  def hexEnc(data: Array[Byte]): String = {
    Hex.toHexString(data);
  }

  def hexDec(str: String): Array[Byte] = {
    Hex.decode(str)
  }

  def ecSignHex(priKey: String, hexHash: String): String = {
    hexEnc(ecSign(priKey, hexHash.getBytes))
  }

  def ecSignHex(priKey: String, hexHash: Array[Byte]): String = {
    hexEnc(ecSign(priKey, hexHash))
  }

  def ecVerifyHex(priKey: String, hexHash: String, signhex: String): Boolean = {
    ecVerify(priKey, hexDec(hexHash), hexDec(signhex));
  }
  def ecVerifyHex(priKey: String, hexHash: Array[Byte], signhex: String): Boolean = {
    ecVerify(priKey, hexHash, hexDec(signhex));
  }

  
  def ecToAddress(contentHash: Array[Byte],r: Array[Byte],s: Array[Byte],v: Byte): Array[Byte] = {
    ECKey.signatureToAddress(contentHash, ECDSASignature.fromComponents(r, s, v));
  }
  def ecToAddress(contentHash: Array[Byte],signBase64:String): Array[Byte] = {
    ECKey.signatureToAddress(contentHash, signBase64);
  }
  def sha3Encode(content: Array[Byte]): Array[Byte] = {
  	  HashUtil.sha3(content);
  }
  def ecToKeyBytes(contentHash: Array[Byte],r: Array[Byte],s: Array[Byte],v: Byte): Array[Byte] = {
    ECKey.signatureToKeyBytes(contentHash, ECDSASignature.fromComponents(r, s, v));
  }
  def ecToKeyBytes(contentHash: Array[Byte],signBase64:String): Array[Byte] = {
    ECKey.signatureToKeyBytes(contentHash, signBase64);
  }
  
  
  def ecVerify(pubKey: String,content: String,r: Array[Byte],s: Array[Byte],v: Byte): Boolean = {
    val key = ECKey.fromPublicOnly(pubKey.getBytes);
    val sig = ECDSASignature.fromComponents(r, s, v);
    key.verify(HashUtil.sha3(content.getBytes), sig);
  }

  def main(args: Array[String]): Unit = {
    val enc = new EncInstance();
    val key = enc.genKeys();
    println("bcuid:" + key.getBcuid)
    println("pri:  " + key.getPrikey);
    println("pub:  " + key.getPubkey);
    println("addr: " + key.getAddress);
    val content = "测试";
    val hash = HashUtil.sha3(content.getBytes);
    println("hash: " + hash)
    val sign = enc.ecSignHex(key.getPrikey, hash);
    println("sign: " + sign)
  }
  
}