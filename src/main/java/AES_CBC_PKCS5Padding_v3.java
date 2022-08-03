/**
 * Created by dhall on 18/04/2017.
 */

// Encryption

import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Base64;
// File Writing
import java.io.BufferedWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
// Exceptions
import java.io.IOException;

/*	Improvements based on:
	https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet#Rule_-_Ensure_that_any_secret_key_is_protected_from_unauthorized_access

	* added cryptographic PRNG seed to generate a random sequences of bytes which are used for the IV.  Implemented in the following methods:
	- encryptAutoIV()

	* adding a HMAC using the EtA approach.  Java Implemented in the following methods:
	- encryptHMAC()
	- decryptHMAC()
	- Java supports - https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac
	- https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac says we have 3 options
	1) Encrypt-then-MAC AKA Encrypt then Authenticate (EtA) = Encrypt the plaintext, MAC the ciphertext + iv then append it to the ciphertext.
	2) MAC-then-Encrypt AKA Authenticate then Encrypt (AtE) = MAC the plaintext then append the MAC to the plaintext then Encrypt it all.
	3) Encrypt-and-MAC AKA Encrypt and Authenticate (E&A) = Encrypt and MAC the plaintext then append the MAC onto the ciphertext.
	- Using advice from https://security.stackexchange.com/questions/20129/how-and-when-do-i-use-hmac/20301 to generate the HMAC
	- The HMAC will be appended to the ciphertext and stored with the encrypted message. - https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_.28EtM.29

	The original implementation which accepts a user supplied IV is availabe in the following methods:
	* encryptUserIV()

	The IV is now prepended to the ciphertext and stored with the encrypted message.
 */

public class AES_CBC_PKCS5Padding_v3
{
	private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");
	private static final Charset CHARSET_ASCII = Charset.forName("US-ASCII");
	private static final String CIPHER_ALGORITHM = "AES";
	private static final String CIPHER_ALGORITHM_MODE_PADDING = "AES/CBC/PKCS5PADDING";
	private static final String HMAC_MODE = "HmacSHA512";
	private static final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
	private static final DateFormat timeFormat = new SimpleDateFormat("HH-mm-ss");

	/**
	 * This method is used to read in all the file's bytes and convert them to a String with a user specified encoding scheme.
	 * File size limitation is 2GB.
	 *
	 * @param inputFilepath       - this contains the file path to the file we are reading in
	 * @param inputEncodingScheme - this contains the encoding the return string will have
	 * @return - will return an encoded string, based on the input file and the encoding parameter
	 * @throws IOException - needed for any file processing exceptions
	 */
	private String readFile(String inputFilepath, Charset inputEncodingScheme) throws IOException
	{
		//create an array of bytes, which holds the read in data from the file.  This is done 1 byte at a time, but using a buffer.
		byte[] fileBytesArrayBase2 = Files.readAllBytes(Paths.get(inputFilepath));
		//return Charset encoded human readable String of Character stream (text file)
		return new String(fileBytesArrayBase2, inputEncodingScheme);
	}

	/**
	 * This method is used to read in Strings and convert them to a file.
	 * The date and time is appended to the filename on output.
	 * The prefix of the filename is determined by the usingCiphertext.
	 *
	 * @param inputEncodedString  - this contains the input string
	 * @param inputEncodingScheme - this contains what encoding the input string has
	 * @param usingCiphertext     - this option is used to determine if the output is ciphertext or plaintext.  True = ciphertext.
	 * @throws IOException - needed for any file processing exceptions
	 */
	private void writeFile(String inputEncodedString, Charset inputEncodingScheme, boolean usingCiphertext) throws IOException
	{
		String currentDate = dateFormat.format(new Date());
		String currentTime = timeFormat.format(new Date());
		//setup filename
		String dateAndTimeAndExtension = new String("_@date_" + currentDate + "_@time_" + currentTime + ".txt");
		//set the output path and filename
		Path outputFilename;
		if (usingCiphertext) {
			outputFilename = Paths.get("ciphertext" + dateAndTimeAndExtension);
			System.out.println(outputFilename);
		}
		else {
			outputFilename = Paths.get("plaintext" + dateAndTimeAndExtension);
			System.out.println(outputFilename);
		}
		//write to file
		BufferedWriter stdoutFile = Files.newBufferedWriter(outputFilename);
		stdoutFile.write(inputEncodedString);
		//need to close and flush the buffer to ensure everything is written to the file
		stdoutFile.close();
	}

	/**
	 * This method is used to read in a String that will be encrypted with AES 128/196/256 CBC PCKS#5 Padding.
	 * The String is encrypted using the user supplied secret key, and with either a user supplied initialisation vector
	 * (IV) or a generated one using a crytopgrahic PRNG seed. The IV is prepended to the ciphertext and returned.
	 *
	 * @param inputPlaintext - this is the user supplied plaintext to be encrypted
	 * @param inputKey       - this is the user supplier secret key
	 * @param inputIV        - this is the user supplier IV, for encryptAutoIV this will be null and automatically created.
	 * @return - this is the ciphertext returned after encryption
	 */
	private String encrypt(String inputPlaintext, String inputKey, String inputIV)
	{
		try {
			// JAVA Cryptography
			// https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html

			// FOR AES 128 = 16 BYTE (128 BIT) KEY, AES 196 = 24BYTE (196 BIT( KEY, AND AES 256 =  32 BYTE (256 BIT) KEY
			// https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/SecretKeySpec.html
			SecretKeySpec secretKeyBytesBase2 = new SecretKeySpec(inputKey.getBytes(CHARSET_UTF8), CIPHER_ALGORITHM);

			// 16 BYTE (128 BIT) INITIALISATION VECTOR
			// https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.html
			IvParameterSpec ivBytesBase2;
			String ivBase64;
			// check for garbage IV, make a good one if the user didn't give us one.
			if (inputIV == null) {
				// create a cryptograhpically strong 16 byte pseudo-random number via the pseudo-random number generator (PRNG).
				// https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html
				SecureRandom pseudorandomNumber = new SecureRandom();
				//get a random series of 16 bytes, store it in an array, and use this as the IV
				byte[] pseudorandomNumberIVBytesArrayBase2 = new byte[16];
				pseudorandomNumber.nextBytes(pseudorandomNumberIVBytesArrayBase2);
				ivBytesBase2 = new IvParameterSpec(pseudorandomNumberIVBytesArrayBase2);
				//convert to base64
				ivBase64 = new String(Base64.getEncoder().encode(pseudorandomNumberIVBytesArrayBase2));

			}
			else {
				ivBytesBase2 = new IvParameterSpec(inputIV.getBytes(CHARSET_UTF8));
				ivBase64 = new String(Base64.getEncoder().encode(inputIV.getBytes(CHARSET_UTF8)));
			}

			// CRYPTORGAPY CIPHER
			// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
			// https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_MODE_PADDING);

			// ENCRYPTION PHASE
			// https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html#init(int,%20java.security.Key,%20java.security.SecureRandom)
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyBytesBase2, ivBytesBase2);
			byte[] encryptedMessageBytesArrayBase2 = cipher.doFinal(inputPlaintext.getBytes());

			// CONVERT BINARY TO BASE64
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			String encryptedMessageBase64 = new String(Base64.getEncoder().encode(encryptedMessageBytesArrayBase2));
			String ciphertextBase64 = ivBase64.concat(encryptedMessageBase64);

			/// OUTPUT IN BASE64
			return ciphertextBase64;

		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	/**
	 * This method is used to read in a String that is encrypted with AES 128/196/256 CBC PCKS#5 Padding.
	 * The String is decrypted it via the supplied secret key and the prepended IV.
	 *
	 * @param inputCiphertextBase64 - this it user supplied ciphertext to be decrypted
	 * @param inputKey              - this is the user supplied secret key
	 * @return - this is the plaintext returned after decryption
	 */
	private String decrypt(String inputCiphertextBase64, String inputKey)
	{
		try {
			// KEY
			SecretKeySpec secretKeyBytesBase2 = new SecretKeySpec(inputKey.getBytes(CHARSET_UTF8), CIPHER_ALGORITHM);

			// INITIALISATION VECTOR EXTRACTION
			//get the first 24 chars which is the IV
			String ivBase64 = inputCiphertextBase64.substring(0, 24);
			//convert the IV back to bytes (
			byte[] ivBytesArrayBase2 = Base64.getDecoder().decode(ivBase64);
			// recreate IV
			IvParameterSpec ivBytesBase2 = new IvParameterSpec(ivBytesArrayBase2);
			//remove the IV from the ciphertext
			String encryptedMessageBase64 = inputCiphertextBase64.substring(ivBase64.length());

			// CRYPTORGAPY CIPHER
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_MODE_PADDING);

			// DECRYPTION PHASE
			cipher.init(Cipher.DECRYPT_MODE, secretKeyBytesBase2, ivBytesBase2);
			byte[] plaintextBytesArrayBase2 = cipher.doFinal(Base64.getDecoder().decode(encryptedMessageBase64));

			// OUTPUT
			// convert bytes to a readable String using new
			return new String(plaintextBytesArrayBase2, CHARSET_UTF8);
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private String getHMAC(String inputCiphertextBase64, String inputKey) throws Exception
	{
		//create MAC object
		Mac hmacSHA512BytesBase2 = Mac.getInstance(HMAC_MODE);
		//create Key object
		SecretKeySpec secretKeyBytesBase2 = new SecretKeySpec(inputKey.getBytes(CHARSET_UTF8), HMAC_MODE);
		//hash stuff
		// 1) convert inputData to binary
		hmacSHA512BytesBase2.init(secretKeyBytesBase2);
		// 2) get the SHA512 HMAC hash of the binary, 512 bits (64 bytes) of binary are returned. Story in a byte array.
		byte[] hmacSHA512BytesArrayBase2 = hmacSHA512BytesBase2.doFinal(inputCiphertextBase64.getBytes(CHARSET_UTF8));
		// 3) convert the result to Base64, which now becomes 88 bytes
		String hmacSHA512Base64 = new String(Base64.getEncoder().encode(hmacSHA512BytesArrayBase2), CHARSET_UTF8);
		return hmacSHA512Base64;
	}

	/**
	 * This method will do encryption on Strings or files using the AES 128 or 196 or 256 Algorithm, in CBC mode, using the PCKS#5 Padding scheme.
	 * It accepts a user supplied initialisation vector (IV).
	 * The encrypted data will be encoded as a Base64 String and outputted as a String or a file.
	 *
	 * @param inputPlaintext - if the useFile is false, this will contain the String.  If the useFile is true, this will contain the file path
	 * @param inputKey       - the user supplierd key being used in the encryption
	 * @param inputIV        - the user supplied IV being used in the encryption
	 * @param useFile        - this determines if this methods works with files or just Strings, true = files and false = Strings
	 * @return - only used if fileFlag is false, when sucessful it will return the Base64 encoded ciphertext otherwise it returns null
	 */
	public String encryptUserIV(boolean useFile, String inputPlaintext, String inputKey, String inputIV, boolean useHMAC)
	{
		try {
			// check if we are using files or Strings
			if (useFile) {
				//grab the path from inputPlaintext
				String filePath = inputPlaintext;
				//overwrite with file contents
				inputPlaintext = readFile(filePath, CHARSET_UTF8);
			}

			//encrypt
			String ciphertextBase64 = encrypt(inputPlaintext, inputKey, inputIV);

			//check if we want a HMAC
			if (useHMAC) {
				//create HMAC and  concatenate the HMAC to the end of the string
				String ciphertextHMACBase64 = getHMAC(ciphertextBase64, inputKey);
				ciphertextBase64 = ciphertextBase64.concat(ciphertextHMACBase64);
			}

			//write to file
			if (useFile) {
				try {
					writeFile(ciphertextBase64, CHARSET_UTF8, true);
				}
				catch (Exception e) {
					System.out.println(e.getMessage());
				}
			}
			//return the string
			else {
				return ciphertextBase64;
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return null;
	}

	/**
	 * This method will do encryption on Strings or files using the AES 128 or 196 or 256 Algorithm, in CBC mode, using the PCKS#5 Padding scheme.
	 * It generates an initialisation vector (IV).
	 * The encrypted data will be encoded as a Base64 String and outputted as a String or a file.
	 *
	 * @param inputPlaintext - if the useFile is false, this will contain the String.  If the useFile is true, this will contain the file path
	 * @param inputKey       - this method should be called with this value as null, but internally it will make it null just to be sure.
	 * @param useFile        - this determines if this methods works with files or just Strings, true = files and false = Strings
	 * @return - only used if fileFlag is false, when sucessful it will return the Base64 encoded ciphertext otherwise it returns null
	 */

	public String encryptAutoIV(boolean useFile, String inputPlaintext, String inputKey, boolean useHMAC)
	{
		try {
			// check if we are using files or Strings
			if (useFile) {
				//grab the path from inputPlaintext
				String filePath = inputPlaintext;
				//overwrite with file contents
				inputPlaintext = readFile(filePath, CHARSET_UTF8);
			}

			//encrypt
			String inputIV = null;
			String ciphertextBase64 = encrypt(inputPlaintext, inputKey, inputIV);

			//check if we want a HMAC
			if (useHMAC) {
				//concatenate the HMAC to the end of the string
				ciphertextBase64 = ciphertextBase64.concat(getHMAC(ciphertextBase64, inputKey));
			}

			//write to file
			if (useFile) {
				try {
					writeFile(ciphertextBase64, CHARSET_UTF8, true);
				}
				catch (Exception e) {
					System.out.println(e.getMessage());
				}
			}
			//return a string
			else {
				return ciphertextBase64;
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return null;
	}

	/**
	 * This method will do decryption on Strings or files using the AES 128 or 196 or 256 Algorithm, in CBC mode, using the PCKS#5 Padding scheme.
	 * It accepts a user supplied initialisation vector (IV).
	 * The decrypted data will be outputted as a String or a file.
	 *
	 * @param inputCiphertextBase64 - if the useFile is false, this will contain the String.  If the useFile is true, this will contain the file path
	 * @param inputKey              - the user supplierd key being used in the encryption
	 * @param useFile               - this determines if this methods works with files or just Strings, true = files and false = Strings
	 * @return - only used if fileFlag is false, when sucessful it will return the Base64 encoded ciphertext otherwise it returns null
	 */
	public String decryptBothIV(boolean useFile, String inputCiphertextBase64, String inputKey, boolean useHMAC)
	{
		try {
			String ciphertextBase64;
			String plaintextBytesBase2;
			String plaintext;

			//check if using a file
			if (useFile) {
				// get path from String parameter
				String filePath = inputCiphertextBase64;
				// overwrite that String parameter
				inputCiphertextBase64 = readFile(filePath, CHARSET_ASCII);
			}

			//check if using HMAC
			if (useHMAC) {
				String originalHMAC;
				String computedHMAC;
				//SHA512 HMAC is 88 bytes long
				// extract the IV + ciphertext
				ciphertextBase64 = inputCiphertextBase64.substring(0, inputCiphertextBase64.length() - 88);
				// compare HMACs to check message integrity
				originalHMAC = inputCiphertextBase64.substring(inputCiphertextBase64.length() - 88);
				computedHMAC = getHMAC(ciphertextBase64, inputKey);
				if (originalHMAC.equals(computedHMAC)) {
					//decrypt
					plaintextBytesBase2 = decrypt(ciphertextBase64, inputKey);
					//Convert to readable String
					plaintext = new String(plaintextBytesBase2);

					// OUTPUT
					if (useFile)
					//write output to file
					{
						writeFile(plaintext, CHARSET_UTF8, false);
					}
					//return a string instead
					else {
						return plaintext;

					}
				}
				else {
					System.out.println("ERROR: The HMAC's did not match, do not trust this mesasge.");
				}
			}
			else {
				ciphertextBase64 = inputCiphertextBase64;

				//decrypt
				plaintextBytesBase2 = decrypt(ciphertextBase64, inputKey);
				//Convert to readable String
				plaintext = new String(plaintextBytesBase2);

				// OUTPUT
				if (useFile)
				//write output to file
				{
					writeFile(plaintext, CHARSET_UTF8, false);
				}
				//return a string instead
				else {
					return new String(plaintext);
				}
			}
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
}