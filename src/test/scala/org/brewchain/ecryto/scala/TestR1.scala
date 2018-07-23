package org.brewchain.ecryto.scala

import org.brewchain.ecrypto.impl.JavaEncR1Instance
import org.brewchain.core.crypto.jni.IPPCrypto
import org.brewchain.ecrypto.impl.NativeEncInstance
import org.brewchain.core.crypto.HashUtil
import org.apache.commons.codec.binary.Hex
import com.googlecode.protobuf.format.util.HexUtils
import org.spongycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi.SHA1
import org.spongycastle.crypto.digests.SHA1Digest
import org.brewchain.core.util.EndianHelper

object TestR1 {
  def main(args: Array[String]): Unit = {
    IPPCrypto.loadLibrary();
    val crypto = new IPPCrypto();
    val natiR1 = NativeEncInstance(crypto);
    val javaR1 = JavaEncR1Instance();
    //    val kp2 = javaR1.genKeys("038e7203310651cd57fe0fb80e21300684d8bb1a751100b6084c8092a3a8750e");
    //    println("kp2.pri=" + kp2.getPrikey + ",pub=" + kp2.getPubkey)
    //    val kp3 = javaR1.genKeys("038e7203310651cd57fe0fb80e21300684d8bb1a751100b6084c8092a3a8750e");
    //    println("kp3.pri=" + kp3.getPrikey + ",pub=" + kp3.getPubkey)
    val jkp = javaR1.genKeys("038e7203310651cd57fe0fb80e21300684d8bb1a751100b6084c8092a3a8750e");
    println("jkp.pri=" + jkp.getPrikey + ",pub=" + jkp.getPubkey)
    val nkp = natiR1.genKeys(jkp.getPrikey);
    println("nkp.pri=" + nkp.getPrikey + ",pub=" + nkp.getPubkey)

    println("check address:" + jkp.getAddress.equals(nkp.getAddress))
    println("check pubkey:" + jkp.getPubkey.equals(nkp.getPubkey))
    println("check prikey:" + jkp.getPrikey.equals(nkp.getPrikey))
    val sha1 = new SHA1Digest();
    val contentHash = HashUtil.sha3("hello".getBytes);
    //    val re_contentHash = EndianHelper.revert(contentHash);
    //    val contentHash = new Array[Byte](32);
    //    sha1.update(contentHash3,0,32);
    //    sha1.doFinal(contentHash,0);
    //    println("contentHash.3="+natiR1.hexEnc(contentHash3))
    println("contentHash=" + natiR1.hexEnc(contentHash))
    val nsign = natiR1.ecSign(jkp.getPrikey, contentHash)
    println("nsign:" + Hex.encodeHexString(nsign))
    //    val nsign2 = natiR1.ecSign(jkp.getPrikey, contentHash)
    //    println("nsign2:" + Hex.encodeHexString(nsign2))
    val jsign = javaR1.ecSign(jkp.getPrikey, contentHash)
    println("jsign:" + Hex.encodeHexString(jsign))
    //    val jsign2 = javaR1.ecSign(jkp.getPrikey, contentHash)
    //    println("jsign2:" + Hex.encodeHexString(jsign2))
    val nverify = natiR1.ecNativeVerify(jkp.getPubkey, contentHash, jsign)
    println("nverify-->java:" + natiR1.ecNativeVerify(jkp.getPubkey, contentHash, jsign))
    println("nverify-->native:" + natiR1.ecNativeVerify(jkp.getPubkey, contentHash, nsign))

    val jverify = javaR1.ecVerify(jkp.getPubkey, contentHash, nsign)
    println("jverify-->native:" + javaR1.ecVerify(jkp.getPubkey, contentHash, nsign))
    println("jverify-->java:" + javaR1.ecVerify(jkp.getPubkey, contentHash, jsign))

  }
}