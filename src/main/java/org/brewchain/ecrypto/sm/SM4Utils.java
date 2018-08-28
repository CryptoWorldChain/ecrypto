package org.brewchain.ecrypto.sm;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;

/**
 * Email: king.camulos@gmail.com Date: 2018/4/3 DESC:
 */
public class SM4Utils {
	private String secretKey = "";
	private String iv = "";
	private boolean hexString = false;

	public SM4Utils() {
	}

	protected String encryptData_ECB(String plainText) {
		try {
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			if (hexString) {
				keyBytes = Util.hexStringToBytes(secretKey);
			} else {
				keyBytes = secretKey.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("GBK"));
			String cipherText = Base64.encodeBase64String(encrypted);
			// new Base64Encoder()(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0) {
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	protected String decryptData_ECB(String cipherText) {
		try {
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			if (hexString) {
				keyBytes = Util.hexStringToBytes(secretKey);
			} else {
				keyBytes = secretKey.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64.decodeBase64(cipherText));
			return new String(decrypted, "GBK");
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	protected String encryptData_CBC(String plainText) {
		try {
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString) {
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			} else {
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("GBK"));
			String cipherText = Base64.encodeBase64String(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0) {
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	protected String decryptData_CBC(String cipherText) {
		try {
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString) {
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			} else {
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Base64.decodeBase64(cipherText));
			return new String(decrypted, "GBK");
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/** 加密ECB */
	public static String getEncStrECB(String inputStr, String secretKey) {
		SM4Utils sm4 = new SM4Utils();
		sm4.secretKey = secretKey;
		sm4.hexString = false;
		String cipherText = sm4.encryptData_ECB(inputStr);
		return cipherText;
	}

	/** 解密ECB */
	public static String getDecStrECB(String inputStr, String secretKey) {
		SM4Utils sm4Util = new SM4Utils();
		sm4Util.secretKey = secretKey;
		sm4Util.hexString = false;
		String plainText = sm4Util.decryptData_ECB(inputStr);
		return plainText;
	}
	/** 加密CBC */
	public static String getEncStrCBC(String inputStr, String secretKey, String iv) {
		SM4Utils sm4 = new SM4Utils();
		sm4.secretKey = secretKey;
		sm4.iv = iv;
		sm4.hexString = false;
		String cipherText = sm4.encryptData_CBC(inputStr);
		return cipherText;
	}

	/** 解密CBC */
	public static String getDecStrCBC(String inputStr, String secretKey, String iv) {
		SM4Utils sm4Util = new SM4Utils();
		sm4Util.secretKey = secretKey;
		sm4Util.iv = iv;
		sm4Util.hexString = false;
		String plainText = sm4Util.decryptData_CBC(inputStr);
		return plainText;
	}
	
}
