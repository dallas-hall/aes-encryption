import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.nio.charset.Charset;
//Java 1.6
//import org.apache.commons.codec.binary.Base64;
//Java 1.8 only
import java.util.Base64;

/**
 * <h1>AES CBC Padding Decryption</h1>
 * <p>
 * This program performs AES 128, 192, or 256 decryption using CBC and PKCS#5 padding.
 * </p>
 *
 * @author dhall
 * @version 0.1 - 2018-02-23
 */
public class AES_CBC_Padding_Decrypt
{
	//@@@ INSTANCE VARIABLES @@@
	private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");
	private static final Charset CHARSET_ASCII = Charset.forName("US-ASCII");
	private static final String CIPHER_ALGORITHM = "AES";
	private static final String CIPHER_ALGORITHM_MODE_PADDING = "AES/CBC/PKCS5PADDING";

	//@@@ METHODS @@@
	//### HELPERS ###
	public static String decrypt(String inputCiphertextBase64, String inputKey)
	{
		try {
			// @@@ JAVA Cryptography @@@
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Introduction

			// ### CREATE SECRET KEY ###
			// 16 BYTE (128 BIT) KEY = AES 128, 24 BYTE (192 BIT) Key = AES 192, 32 BYTE (256 BIT) Key = AES 256
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/SecretKeySpec.html
			SecretKeySpec secretKeyBytesBase2 = new SecretKeySpec(inputKey.getBytes(CHARSET_UTF8), CIPHER_ALGORITHM);

			// ### INITIALISATION VECTOR EXTRACTION ###
			// Get the first 24 chars which is the IV
			String ivBase64 = inputCiphertextBase64.substring(0, 24);
			// Convert the IV back to bytes
			// Java 1.6
			//byte[] ivBytesArrayBase2 = Base64.decodeBase64(ivBase64);
			// Java 1.8
			byte[] ivBytesArrayBase2 = Base64.getDecoder().decode(ivBase64);
			// Recreate IV
			IvParameterSpec ivBytesBase2 = new IvParameterSpec(ivBytesArrayBase2);
			// Remove the IV from the ciphertext
			String encryptedMessageBase64 = inputCiphertextBase64.substring(ivBase64.length());

			// @@@ CRYPTOGRAPHY CIPHER @@@
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_MODE_PADDING);

			// @@@ DECRYPTION PHASE @@@
			cipher.init(Cipher.DECRYPT_MODE, secretKeyBytesBase2, ivBytesBase2);
			// Java 1.6
			//byte[] plaintextBytesArrayBase2 = cipher.doFinal(Base64.decodeBase64(encryptedMessageBase64));
			// Java 1.8 only
			byte[] plaintextBytesArrayBase2 = cipher.doFinal(Base64.getDecoder().decode(encryptedMessageBase64));

			// @@@ OUTPUT @@@
			// convert bytes to a readable String using new
			return new String(plaintextBytesArrayBase2, CHARSET_UTF8);
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

}
