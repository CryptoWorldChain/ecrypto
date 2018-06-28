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
import org.brewchain.core.crypto.jni.IPPCrypto
import org.brewchain.core.util.ByteUtil
import java.util.Arrays

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
  
  var clibLoad:Boolean = false;
  var crypto:IPPCrypto = null;
	def startup() {
    try{
    		  IPPCrypto.loadLibrary();
    		  clibLoad = true;
    		  crypto = new IPPCrypto();
        log.info("CLibs加载成功");
    }catch{
        case e: Throwable => println(e);
        clibLoad = false;
        crypto = null;
        log.info("CLibs加载失败");
    }
  }
  
  def nextUID(key: String = "BCC2018"): String = {
    //    val id = UUIG.generate()
    val ran = new SecureRandom(key.getBytes);
    //ran.generateSeed(System.currentTimeMillis().asInstanceOf[Int])
    val eckey = new ECKey(ran);
    val encby = HashUtil.ripemd160(eckey.getPubKey);
    //    println("hex=" + Hex.toHexString(encby))
    val i = BigInt(Hex.toHexString(encby), 16)
    //    println("i=" + i)
    val id = hexToMapping(i)
    val mix = BCNodeHelper.mixStr(id, key);
    mix + SessionIDGenerator.genSum(mix)
  }

  override def getModule: String = "BIP"
  override def getCmds: Array[String] = Array("ENC");
  def priKeyToAddress(privKey: String): String={
    return "";
  }
  
  
  def genKeys(): KeyPairs = {
    if(clibLoad && crypto != null){
			val pk = new Array[Byte](32);
			val x= new Array[Byte](32);
			val y= new Array[Byte](32);
			crypto.genKeys(null,pk, x, y);
			val pubKeyByte = ByteUtil.merge(x,y);
			val privKey = hexEnc(pk);
			val pubKey = hexEnc(pubKeyByte);
			val address = hexEnc(Arrays.copyOfRange(sha256Encode(pubKeyByte), 0, 20));
			val kp = new KeyPairs(
          pubKey,
          privKey,
          address,
          nextUID(pubKey));
        return kp;
    } else {
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
    }
  };
  
  def genKeys(seed:String): KeyPairs = {
    if(clibLoad && crypto != null){
      val pk = new Array[Byte](32);
			val x= new Array[Byte](32);
			val y= new Array[Byte](32);
			crypto.genKeys(HashUtil.sha3(seed.getBytes()),pk, x, y);
			val pubKeyByte = ByteUtil.merge(x,y);
			val privKey = hexEnc(pk);
			val pubKey = hexEnc(pubKeyByte);
			val address = hexEnc(Arrays.copyOfRange(sha256Encode(pubKeyByte), 0, 20));
			val kp = new KeyPairs(
          pubKey,
          privKey,
          address,
          nextUID(pubKey));
        return kp;
    }else{
      val eckey = ECKey.fromPrivate(HashUtil.sha3(seed.getBytes()))
      val pubstr = Hex.toHexString(eckey.getPubKey);
      val kp = new KeyPairs(
        hexEnc(eckey.getPubKey),
        Hex.toHexString(eckey.getPrivKeyBytes),
        Hex.toHexString(eckey.getAddress),
        nextUID(pubstr));
      return kp
    }
  };
  

  
  def ecEncode(pubKey: String, content: Array[Byte]): Array[Byte] = {
    val eckey = ECKey.fromPublicOnly(Hex.decode(pubKey));
    val encBytes = ECIESCoder.encrypt(eckey.getPubKeyPoint, content);
    encBytes;
  }

  def ecDecode(priKey: String, content: Array[Byte]): Array[Byte] = {
    val eckey = ECKey.fromPrivate(Hex.decode(priKey));
    val orgBytes = ECIESCoder.decrypt(eckey.getPrivKey, content);
    orgBytes;
  }

  def ecSign(priKey: String, contentHash: Array[Byte]): Array[Byte] = {
    
    if(clibLoad){
      val privKeyBytes:Array[Byte] = Hex.decode(priKey);
			val x= new Array[Byte](32);
			val y= new Array[Byte](32);
			if(crypto.fromPrikey(privKeyBytes, x, y)){
			  val s= new Array[Byte](32);
			  val a= new Array[Byte](32);
			  if(crypto.signMessage(privKeyBytes, x, y, contentHash, s, a)){
      			val signBytes = ByteUtil.merge(x,y,Arrays.copyOfRange(sha256Encode(ByteUtil.merge(x,y)), 0, 20),s,a);
      			return signBytes;
      		}
			}
    }
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
    if(clibLoad){
      val pubKeyBytes = Hex.decode(pubKey);
      val x = Arrays.copyOfRange(pubKeyBytes, 0, 32);
      val y = Arrays.copyOfRange(pubKeyBytes, 32, 64);
      val s = Arrays.copyOfRange(sign, 84, 116);
      val a = Arrays.copyOfRange(sign, 116, 148);
      crypto.verifyMessage(x, y, contentHash, s, a);
    }else{
      val eckey = ECKey.fromPublicOnly(Hex.decode(pubKey));
      eckey.verify(contentHash, sign);
    }
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

  def ecVerifyHex(pubKey: String, hexHash: String, signhex: String): Boolean = {
    ecVerify(pubKey, hexDec(hexHash), hexDec(signhex));
  }
  def ecVerifyHex(pubKey: String, hexHash: Array[Byte], signhex: String): Boolean = {
    ecVerify(pubKey, hexHash, hexDec(signhex));
  }

  
  
  def sha3Encode(content: Array[Byte]): Array[Byte] = {
  	HashUtil.sha3(content);
  }
  def sha256Encode(content: Array[Byte]): Array[Byte] = {
  	HashUtil.sha256(content);
  }
  
  
  
  def ecToKeyBytes(pubKey: String,content: String): String = {
    val key = ECKey.fromPublicOnly(pubKey.getBytes);
    val contentHash = HashUtil.sha256(content.getBytes);
    val sig = key.doSign(contentHash);
    hexEnc(ECKey.signatureToKeyBytes(contentHash, sig));
  }
  
  def ecToAddress(contentHash: Array[Byte], signBase64: String): Array[Byte] = {
    if(clibLoad){
      Arrays.copyOfRange(base64Dec(signBase64),64,84);
    }else{
      ECKey.signatureToAddress(contentHash, signBase64);
    }
  }
  
  def ecToKeyBytes(contentHash: Array[Byte], signBase64: String): Array[Byte] = {
    if(clibLoad){
      Arrays.copyOfRange(base64Dec(signBase64),0,64);
    }else{
      ECKey.signatureToKeyBytes(contentHash, signBase64);
    }
  }

}