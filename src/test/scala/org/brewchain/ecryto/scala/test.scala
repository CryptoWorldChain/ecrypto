package org.brewchain.ecryto.scala

import org.brewchain.ecrypto.impl.JavaEncInstance
import org.brewchain.ecrypto.impl.NativeEncInstance
import org.brewchain.core.crypto.jni.IPPCrypto
import com.googlecode.protobuf.format.util.HexUtils
import org.spongycastle.util.encoders.Hex

object Test {

  def main(args: Array[String]): Unit = {
    val javaEnc = JavaEncInstance();
    IPPCrypto.loadLibrary();

    val crypto = new IPPCrypto();
    val natiEnc = NativeEncInstance(crypto);
    val count = 1;
    val jkp = javaEnc.genKeys();
    val nkp = natiEnc.genKeys();
    println("sig.java==" + jkp.getPrikey)
    println("sig.nati==" + nkp.getPrikey)

    var st = System.currentTimeMillis();
    val jhash = javaEnc.sha256Encode("hash111".getBytes);
    val jsignbyte = javaEnc.ecSign(jkp.getPrikey, jhash);
    //    for (i <- 1 to count) {
    //      javaEnc.ecSign(jkp.getPrikey,jhash );
    //    }
    println("java signed cost=" + (System.currentTimeMillis() - st));

    st = System.currentTimeMillis();
    val nhash = natiEnc.sha256Encode("hash111".getBytes);
    //    for (i <- 1 to count) {
    //      val signbyte = natiEnc.ecSign(nkp.getPrikey, nhash);
    //    }
    val nsignbyte = natiEnc.ecSign(nkp.getPrikey, nhash);
    println("nati signed cost=" + (System.currentTimeMillis() - st));

    st = System.currentTimeMillis();
    //    for (i <- 1 to count) {
    //      javaEnc.ecVerify(jkp.getPubkey, javaEnc.sha256Encode("hash111".getBytes), jsignbyte);
    //    }
    println("java verify cost=" + (System.currentTimeMillis() - st) + ":" + javaEnc.ecVerify(jkp.getPubkey, nhash, jsignbyte));

    println("native.ecsign=" + Hex.toHexString(nsignbyte))
    st = System.currentTimeMillis();
    for (i <- 1 to count) {
      natiEnc.ecVerify(nkp.getPubkey, nhash, nsignbyte);
    }
    println("nati verify cost=" + (System.currentTimeMillis() - st) + ":" + natiEnc.ecVerify(nkp.getPubkey, nhash, nsignbyte));

    st = System.currentTimeMillis();
    for (i <- 1 to count) {
      javaEnc.sha256Encode("hash111".getBytes);
    }
    println("java hash256 cost=" + (System.currentTimeMillis() - st));

    st = System.currentTimeMillis();
    for (i <- 1 to count) {
      natiEnc.sha256Encode("hash111".getBytes);
    }
    println("nati hash256 cost=" + (System.currentTimeMillis() - st));

    st = System.currentTimeMillis();
    for (i <- 1 to count) {
      javaEnc.sha3Encode("hash111".getBytes);
    }
    println("java hash3 cost=" + (System.currentTimeMillis() - st));

    st = System.currentTimeMillis();
    for (i <- 1 to count) {
      natiEnc.sha3Encode("hash111".getBytes);
    }
    println("nati hash3 cost=" + (System.currentTimeMillis() - st));

    println("jhash256=" + javaEnc.hexEnc(javaEnc.sha256Encode("hash111".getBytes)))
    println("nhash256=" + natiEnc.hexEnc(natiEnc.sha256Encode("hash111".getBytes)))

    println("jhash3=" + javaEnc.hexEnc(javaEnc.sha3Encode("hash111".getBytes)))
    println("nhash3=" + natiEnc.hexEnc(natiEnc.sha3Encode("hash111".getBytes)))

    val kp=natiEnc.priKeyToKey("29f8a7d7d99253e8a1714e37ac2d95ac058e12fe4bbcfe634d70d443a7b75527");
    println("prikey="+kp.getPrikey)
    println("pubkey="+kp.getPubkey)
    //    println(javaEnc.hexEnc(signbyte));

  }
}