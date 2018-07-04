package org.brewchain.ecrypto.impl

import java.security.SecureRandom

import scala.BigInt

import org.apache.commons.codec.binary.Base64
import org.brewchain.core.crypto.ECIESCoder
import org.brewchain.core.crypto.ECKey
import org.brewchain.core.crypto.HashUtil
import org.fc.brewchain.bcapi.KeyPairs
import org.fc.brewchain.bcapi.crypto.BCNodeHelper
import org.fc.brewchain.bcapi.crypto.BitMap
import org.spongycastle.util.encoders.Hex

import onight.tfw.outils.serialize.SessionIDGenerator
trait EncTrait extends BitMap {
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

  def genKeys(): KeyPairs;
  def genKeys(seed: String): KeyPairs;

  def ecSign(priKey: String, contentHash: Array[Byte]): Array[Byte];

  def ecVerify(pubKey: String, contentHash: Array[Byte], sign: Array[Byte]): Boolean;

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

  def sha3Encode(content: Array[Byte]): Array[Byte];
  def sha256Encode(content: Array[Byte]): Array[Byte];

//  def ecToKeyBytes(pubKey: String, content: String): String;

  def ecToAddress(contentHash: Array[Byte], sign: String): Array[Byte];

  def ecToKeyBytes(contentHash: Array[Byte], sign: String): Array[Byte];

  def priKeyToKey(privKey: String): KeyPairs;
}
