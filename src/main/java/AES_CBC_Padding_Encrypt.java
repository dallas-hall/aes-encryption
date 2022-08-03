import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.security.SecureRandom;
//Java 1.6
//import org.apache.commons.codec.binary.Base64;
//Java 1.8 only
import java.util.Base64;

/**
 * <h1>AES CBC Padding Encryption</h1>
 * <p>
 * This program performs AES 128, 192, or 256 encryption using CBC and PKCS#5 padding.
 * </p>
 *
 * @author dhall
 * @version 0.1 - 2018-02-23
 */
public class AES_CBC_Padding_Encrypt
{
	//@@@ INSTANCE VARIABLES @@@
	private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");
	private static final Charset CHARSET_ASCII = Charset.forName("US-ASCII");
	private static final String CIPHER_ALGORITHM = "AES";
	private static final String CIPHER_ALGORITHM_MODE_PADDING = "AES/CBC/PKCS5PADDING";

	//@@@ METHODS @@@
	//### HELPERS ###
	public static String encrypt(String inputPlainText, String inputKey)
	{
		try {
			// @@@ JAVA Cryptography @@@
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Introduction

			// ### CREATE SECRET KEY ###
			// 16 BYTE (128 BIT) KEY = AES 128, 24 BYTE (192 BIT) Key = AES 192, 32 BYTE (256 BIT) Key = AES 256
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/SecretKeySpec.html
			SecretKeySpec secretKeyBytesBase2 = new SecretKeySpec(inputKey.getBytes(CHARSET_UTF8), CIPHER_ALGORITHM);

			// ### CREATE INITIALISATION VECTOR ###
			// 16 BYTE (128 BIT) IV
			// Create a cryptograhpically strong 16 byte pseudo-random number via the pseudo-random number generator (PRNG).
			// by getting a random series of 16 bytes, store it in an array, and use this as the IV
			// https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html
			SecureRandom pseudoRandomNumber = new SecureRandom();
			byte[] prnBytesArrayBase2 = new byte[16];
			pseudoRandomNumber.nextBytes(prnBytesArrayBase2);

			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/IvParameterSpec.html
			IvParameterSpec ivBytesBase2 = new IvParameterSpec(prnBytesArrayBase2);
			//convert to base64
			// Java 1.6
			//String ivBase64 = new String(Base64.encodeBase64String(prnBytesArrayBase2));
			// Java 1.8
			String ivBase64 = new String(Base64.getEncoder().encode(prnBytesArrayBase2));

			// ### CRYPTOGRAPHY CIPHER ###
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_MODE_PADDING);

			// ### ENCRYPTION PHASE ###
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html#init(int,%20java.security.Key,%20java.security.SecureRandom)
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyBytesBase2, ivBytesBase2);
			byte[] encryptedMessageBytesArrayBase2 = cipher.doFinal(inputPlainText.getBytes());

			// ### CONVERT BINARY TO BASE64 ###
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			// Java 1.6
			//String encryptedMessageBase64 = new String(Base64.encodeBase64String(encryptedMessageBytesArrayBase2));
			// Java 1.8
			String encryptedMessageBase64 = new String(Base64.getEncoder().encode(encryptedMessageBytesArrayBase2));
			// Prepend IV to ciphertext
			String ciphertextBase64 = ivBase64.concat(encryptedMessageBase64);

			/// OUTPUT IN BASE64
			return ciphertextBase64;
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
}
