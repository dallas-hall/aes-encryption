/**
 * Created by dhall on 18/04/2017.
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import java.util.Base64; //Java 1.8 only
import org.apache.commons.codec.binary.Base64;

public class AES_CBC_PKCS5Padding_Java16
{
	public String encrypt(String inputPlainText, String inputKey, String inputIV)
	{
		try
		{
			// JAVA Cryptography
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Introduction

			// 16 BYTE (128 BIT) KEY \\
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/SecretKeySpec.html
			SecretKeySpec secretKey = new SecretKeySpec(inputKey.getBytes("UTF-8"), "AES");

			// 16 BYTE (128 BIT) INITIALISATION VECTOR \\
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/IvParameterSpec.html
			IvParameterSpec iv = new IvParameterSpec(inputIV.getBytes("UTF-8"));

			// CRYPTORGAPY CIPHER \\
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

			// ENCRYPTION PHASE \\
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html#init(int,%20java.security.Key,%20java.security.SecureRandom)
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
			byte[] encrypted = cipher.doFinal(inputPlainText.getBytes());

			// CONVERT BINARY TO BASE64 \\
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			//String encryptedBase64 = new String(Base64.getEncoder().encode(encrypted)); //Java 1.8 only
			String encryptedBase64 =  new String(Base64.encodeBase64String(encrypted));

			/// OUTPUT IN BASE64 \\
			return encryptedBase64;
		} catch (Exception ex)
		{
			ex.printStackTrace();
		}
		return null;
	}

	public String decrypt(String encryptedString, String inputKey, String inputIV)
	{
		try
		{
			// KEY \\
			SecretKeySpec secretKey = new SecretKeySpec(inputKey.getBytes("UTF-8"), "AES");

			// INITIALISATION VECTOR \\
			IvParameterSpec iv = new IvParameterSpec(inputIV.getBytes("UTF-8"));

			// CRYPTORGAPY CIPHER \\
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

			// DECRYPTION PHASE \\
			cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
			//byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedString)); //Java 1.8 only
			byte[] original = cipher.doFinal(Base64.decodeBase64(encryptedString));

			// OUTPUT \\
			return new String(original);
		} catch (Exception ex)
		{
			ex.printStackTrace();
		}
		return null;
	}
}
