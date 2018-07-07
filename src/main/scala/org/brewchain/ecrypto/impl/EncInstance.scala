package org.brewchain.ecrypto.impl

import java.util.List

import scala.beans.BeanProperty

import org.apache.felix.ipojo.annotations.Instantiate
import org.apache.felix.ipojo.annotations.Provides
import org.apache.felix.ipojo.annotations.ServiceProperty
import org.apache.felix.ipojo.annotations.Validate
import org.brewchain.core.crypto.jni.IPPCrypto
import org.brewchain.ecrypto.address.AddressEnum
import org.brewchain.ecrypto.address.AddressFactory
import org.fc.brewchain.bcapi.EncAPI
import org.fc.brewchain.bcapi.KeyPairs
import org.fc.brewchain.bcapi.crypto.BitMap

import com.google.protobuf.Message

import onight.oapi.scala.commons.PBUtils
import onight.oapi.scala.commons.SessionModules
import onight.oapi.scala.traits.OLog
import onight.osgi.annotation.NActorProvider
import onight.tfw.ntrans.api.ActorService

@NActorProvider
@Instantiate(name = "bc_encoder")
@Provides(specifications = Array(classOf[ActorService], classOf[EncAPI]), strategy = "SINGLETON")
class EncInstance extends SessionModules[Message] with BitMap with PBUtils with OLog with EncAPI with ActorService {

  @ServiceProperty(name = "name")
  @BeanProperty
  var name: String = "bc_encoder";

  //  def apply(bundleContext: BundleContext): EncInstance = {
  //    log.debug("apply:bundleContext=" + bundleContext)
  //    this
  //  }

  //  def apply(): EncInstance = {
  //    log.debug("Apply()=")
  //    this
  //  }

  var enc: EncTrait = null;
  //  var btc: EncTrait = JavaBtcInstance();

  @Validate
  def startup() {
    try {
      IPPCrypto.loadLibrary();
      var crypto = new IPPCrypto();
      enc = NativeEncInstance(crypto);
      log.info("CLibs loading success:" + crypto);
    } catch {
      case e: Throwable =>
        enc = JavaEncInstance()
        println(e);
        log.info("CLibs loading fail", e);
    }
  }
  override def isReady: Boolean = {
    enc != null;
  }

  override def getModule: String = "BIP"
  override def getCmds: Array[String] = Array("ENC");

  def priKeyToAddress(privKey: String): String = {
    val key = enc.priKeyToKey(privKey);
    if (key != null) {
      key.getAddress
    } else {
      null
    }
  }

  def priKeyToPubKey(privKey: String): String = {
    val key = enc.priKeyToKey(privKey);
    if (key != null) {
      key.getPubkey
    } else {
      null
    }
  }

  def priKeyToKey(privKey: String): KeyPairs = {
    return enc.priKeyToKey(privKey);
  }

  def genIOTAKeys(seed: String, security: Int, index: Int, checksum: Boolean, total: Int, returnAll: Boolean): List[String] = {
    val newAddr = AddressFactory.create(AddressEnum.IOTA);
    newAddr.newAddress(seed, security, index, checksum, total, returnAll);
  }

  def genBTCKeys(): KeyPairs = {
    enc.genKeys()
  };

  def genKeys(): KeyPairs = {
    enc.genKeys()
  };

  def genKeys(seed: String): KeyPairs = {
    enc.genKeys(seed)
  };

  def ecSign(priKey: String, contentHash: Array[Byte]): Array[Byte] = {
    enc.ecSign(priKey, contentHash);
  }

  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean = {
    enc.ecVerify(pubKey, contentHash, sign);
  }

  def base64Enc(data: Array[Byte]): String = {
    //    Base64.encodeBase64String(data);
    enc.base64Enc(data);
  }

  def base64Dec(str: String): Array[Byte] = {
    //    Base64.decodeBase64(str);
    enc.base64Dec(str);
  }

  def hexEnc(data: Array[Byte]): String = {
    enc.hexEnc(data)
  }

  def hexDec(str: String): Array[Byte] = {
    enc.hexDec(str)
  }

  def ecSignHex(priKey: String, hexHash: String): String = {
    //    hexEnc(ecSign(priKey, hexHash.getBytes))
    enc.ecSignHex(priKey, hexHash);
  }

  def ecSignHex(priKey: String, hexHash: Array[Byte]): String = {
    //    hexEnc(ecSign(priKey, hexHash))
    enc.ecSignHex(priKey, hexHash);
  }

  def ecVerifyHex(pubKey: String, hexHash: String, signhex: String): Boolean = {
    //    ecVerify(pubKey, hexDec(hexHash), hexDec(signhex));
    enc.ecVerifyHex(pubKey, hexHash, signhex);
  }
  def ecVerifyHex(pubKey: String, hexHash: Array[Byte], signhex: String): Boolean = {
    enc.ecVerifyHex(pubKey, hexHash, signhex);
  }

  def sha3Encode(content: Array[Byte]): Array[Byte] = {
    enc.sha3Encode(content)
  }
  def sha256Encode(content: Array[Byte]): Array[Byte] = {
    enc.sha256Encode(content)
  }

  //  def ecToKeyBytes(pubKey: String, content: String): String = {
  //    enc.ecToKeyBytes(pubKey,content)
  //  }

  def ecToAddress(contentHash: Array[Byte], sign: String): Array[Byte] = {
    enc.ecToAddress(contentHash, sign);
  }

  def ecToKeyBytes(contentHash: Array[Byte], sign: String): Array[Byte] = {
    enc.ecToKeyBytes(contentHash, sign);
  }

}