/**
 * Created by dhall on 23/03/2018.
 */
public class Test_AES_CBC_PKCS5Padding_v2
{
	private AES_CBC_PKCS5Padding_v3 testingRun = new AES_CBC_PKCS5Padding_v3();

	public static void main(String[] args)
	{
/*		IMPORTANT NOTE
		http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html

		The maximum keysize by default is 128bit, if stronger algorithms are needed (for example, AES with 256-bit keys), the  JCE Unlimited Strength Jurisdiction Policy Files must be obtained and installed in the JDK/JRE.
 */

/*
		// test file encryption with HMAC and auto IV
		//Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithFileHMACautoIV = new Test_AES_CBC_PKCS5Padding_v2(true, true, true, true, "I can eat glass.txt", "0123456789ABCDEF", null);
		// test file decryption with HMAC and auto IV
		//Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithFileHMACautoIV = new Test_AES_CBC_PKCS5Padding_v2(true, false, true, true, "ciphertext_@date_2017-10-26_@time_21-52-23.txt", "0123456789ABCDEF", null);
*/

/*		// test file encryption with HMAC and user IV
		//Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithFileHMAC = new Test_AES_CBC_PKCS5Padding_v2(true, true, true, false, "I can eat glass.txt", "0123456789ABCDEF", "1248163264128256");
		// test file decryption with HMAC and user IV
		//Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithFileHMAC = new Test_AES_CBC_PKCS5Padding_v2(true, false, true, false, "ciphertext@2017-05-18_04-37-18.txt", "0123456789ABCDEF", "1248163264128256");*/

		// test file encryption without HMAC and auto IV
		//Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithFileautoIV = new Test_AES_CBC_PKCS5Padding_v2(true, true, false, true, "src/main/resources/I can eat glass.txt", "0123456789ABCDEF", null);
		// test file decryption without HMAC and auto IV
		Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithFileautoIV = new Test_AES_CBC_PKCS5Padding_v2(true, false, false, true, "ciphertext_@date_2018-03-23_@time_14-52-34.txt", "0123456789ABCDEF", null);

/*		// test file encryption without HMAC and user IV
		Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithFile = new Test_AES_CBC_PKCS5Padding_v2(true, true, false, false, "I can eat glass.txt", "0123456789ABCDEF", "1248163264128256");
		// test file decryption without HMAC and user IV
		Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithFile = new Test_AES_CBC_PKCS5Padding_v2(true, false, false, false, "", "0123456789ABCDEF", "1248163264128256");*/

/*		// test string encryption with HMAC and auto IV
		Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithOutFileHMACautoIV = new Test_AES_CBC_PKCS5Padding_v2(false, true, true, true, null, "0123456789ABCDEF", null);
		// test string decryption with HMAC and auto IV
		Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithOutFileHMACautoIV = new Test_AES_CBC_PKCS5Padding_v2(false, false, true, true, null, "0123456789ABCDEF", null);*/

/*		// test string encryption with HMAC and user IV
		//Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithOutFileHMAC = new Test_AES_CBC_PKCS5Padding_v2(false, true, true, false, "Liverpool FC are back in the Champions League!", "0123456789ABCDEF", "1248163264128256");
		// test string decryption with HMAC and user IV
		Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithOutFileHMAC = new Test_AES_CBC_PKCS5Padding_v2(false, false, true, false, "MTI0ODE2MzI2NDEyODI1Ng==Ry4Uxqn3LmHQCnEjN1217iRNziASBQez27lFA/9Gk2Q=8yNHGO7ZifC1TE8FETx7ayeWxDlLihJ59iS91yyzbGSGSPDRF8XwnqHQBmbWKxfMETFk2iMy8pvqBGR18BRyGg==", "0123456789ABCDEF", "1248163264128256");*/

/*		// test string encryption without HMAC and auto IV
		//Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithOutFileautoIV = new Test_AES_CBC_PKCS5Padding_v2(false, true, false, true, "Liverpool FC are back in the Champions League!", "0123456789ABCDEF", null);
		// decrypt a string without HMAC and auto IV
		//Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithOutFileautoIV = new Test_AES_CBC_PKCS5Padding_v2(false, false, false, true, "CZVTmylsvcdcx3UqmdZTEQ==gx9lGK0q2F6JXSJnVrgUR/MraFzLeec2yItwlAmHbWm1+RNeZc8BF/AM/6CcBufI", "0123456789ABCDEF", null);*/

/*		// test string encryption without HMAC and user IV
		//Test_AES_CBC_PKCS5Padding_v2 testingEncryptionWithOutFile = new Test_AES_CBC_PKCS5Padding_v2(false, true, false, false, "Liverpool FC are back in the Champions League!", "0123456789ABCDEF", "1248163264128256");*/
		// decrypt a string without HMAC and user IV
		//Test_AES_CBC_PKCS5Padding_v2 testingDecryptionWithOutFile = new Test_AES_CBC_PKCS5Padding_v2(false, false, false, false, "2v9qAmJ5JU+W4xII8OnLiQ==", "1234567890123456", null);
	}

	/**
	 * This constructor organises which test case to call, based on the combination of flags below.
	 *
	 * @param isFile       - True = working with an input file. False = working with an input String.
	 * @param isEncrypting - True = encryption rounds. False = decryption rounds.
	 * @param usingHMAC    True = Use HMAC. False = don't use HMAC.
	 * @param usingAutoIV  True = Use automatic IV.  False = Use user input IV.
	 */
	public Test_AES_CBC_PKCS5Padding_v2(boolean isFile, boolean isEncrypting, boolean usingHMAC, boolean usingAutoIV, String inputFilepath, String inputKey, String inputIV)
	{
		/* ENCRYPTION */
		// test file encryption with HMAC and auto IV
		if (isFile && isEncrypting && usingHMAC && usingAutoIV) {
			testFileEncryption(true, true, inputFilepath, inputKey, inputIV);
		}
		// test file encryption with HMAC and user IV
		else if (isFile && isEncrypting && usingHMAC && !usingAutoIV) {
			testFileEncryption(true, false, inputFilepath, inputKey, inputIV);
		}
		// test file encryption without HMAC and auto IV
		else if (isFile && isEncrypting && !usingHMAC && usingAutoIV) {
			testFileEncryption(false, true, inputFilepath, inputKey, inputIV);
		}
		// test file encryption without HMAC and user IV
		else if (isFile && isEncrypting && !usingHMAC && !usingAutoIV) {
			testFileEncryption(false, false, inputFilepath, inputKey, inputIV);
		}
		// test string encryption with HMAC and auto IV
		else if (!isFile && isEncrypting && usingHMAC && usingAutoIV) {
			testStringEncryption(true, true, inputFilepath, inputKey, inputIV);
		}
		// test string encryption with HMAC and user IV
		else if (!isFile && isEncrypting && usingHMAC && !usingAutoIV) {
			testStringEncryption(true, false, inputFilepath, inputKey, inputIV);
		}
		// test string encryption without HMAC and auto IV
		else if (!isFile && isEncrypting && !usingHMAC && usingAutoIV) {
			testStringEncryption(false, true, inputFilepath, inputKey, inputIV);
		}
		// test string encryption without HMAC and user IV
		else if (!isFile && isEncrypting && !usingHMAC && !usingAutoIV) {
			testStringEncryption(false, false, inputFilepath, inputKey, inputIV);
		}
		/* DECRYPTION */
		// test file decryption with HMAC and auto IV
		else if (isFile && !isEncrypting && usingHMAC && usingAutoIV) {
			testFileDecryption(true, inputFilepath, inputKey);
		}
		// test file decryption with HMAC and user IV
		else if (isFile && !isEncrypting && usingHMAC && !usingAutoIV) {
			testFileDecryption(true, inputFilepath, inputKey);
		}
		// test file decryption without HMAC and auto IV
		else if (isFile && !isEncrypting && !usingHMAC && usingAutoIV) {
			testFileDecryption(false, inputFilepath, inputKey);
		}
		// test file decryption without HMAC and user IV
		else if (isFile && !isEncrypting && !usingHMAC && !usingAutoIV) {
			testFileDecryption(false, inputFilepath, inputKey);
		}
		// test string decryption with HMAC and auto IV
		else if (!isFile && !isEncrypting && usingHMAC && usingAutoIV) {
			testStringDecryption(false, inputFilepath, inputKey);
		}
		// test string decryption with HMAC and user IV
		else if (!isFile && !isEncrypting && usingHMAC && !usingAutoIV) {
			testStringDecryption(true, inputFilepath, inputKey);
		}
		// test string decryption without HMAC and auto IV
		else if (!isFile && !isEncrypting && !usingHMAC && usingAutoIV) {
			testStringDecryption(false, inputFilepath, inputKey);
		}
		// test string decryption without HMAC and user IV
		else if (!isFile && !isEncrypting && !usingHMAC && !usingAutoIV) {
			testStringDecryption(false, inputFilepath, inputKey);
		}
		else {
			System.out.println("ERROR: invalid combination somehow occured.");
		}
	}

	private void testFileEncryption(boolean usingHMAC, boolean usingAutoIV, String inputFilepath, String inputKey, String inputIV)
	{
		try {
			if (usingHMAC && !usingAutoIV) {
				// User IV & HMAC
				testingRun.encryptUserIV(true, inputFilepath, inputKey, inputIV, true);
			}
			else if (!usingHMAC && !usingAutoIV) {
				// User IV & No HMAC
				testingRun.encryptUserIV(true, inputFilepath, inputKey, inputIV, false);
			}
			else if (usingHMAC && usingAutoIV) {
				// Auto IV & HMAC
				testingRun.encryptAutoIV(true, inputFilepath, inputKey, true);
			}
			else if (!usingHMAC && usingAutoIV) {
				// Auto IV & No HMAC
				testingRun.encryptAutoIV(true, inputFilepath, inputKey, false);
			}
			else {
				System.out.println("ERROR: invalid combination somehow occured.");
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	private void testStringEncryption(boolean usingHMAC, boolean usingAutoIV, String inputPlaintext, String inputKey, String inputIV)
	{
		try {
			if (usingHMAC && !usingAutoIV) {
				// User IV & HMAC
				System.out.println(testingRun.encryptUserIV(false, inputPlaintext, inputKey, inputIV, true));
			}
			else if (!usingHMAC && !usingAutoIV) {
				// User IV & No HMAC
				System.out.println(testingRun.encryptUserIV(false, inputPlaintext, inputKey, inputIV, false));
			}
			else if (usingHMAC && usingAutoIV) {
				// Auto IV & HMAC
				System.out.println(testingRun.encryptAutoIV(false, inputPlaintext, inputKey, true));
			}
			else if (!usingHMAC && usingAutoIV) {
				// Auto IV & No HMAC
				System.out.println(testingRun.encryptAutoIV(false, inputPlaintext, inputKey, false));
			}
			else {
				System.out.println("ERROR: invalid combination somehow occured.");
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	private void testFileDecryption(boolean usingHMAC, String inputFilepath, String inputKey)
	{
		try {
			if (usingHMAC) {
				// User or Auto IV & HMAC
				testingRun.decryptBothIV(true, inputFilepath, inputKey, true);
			}
			else {
				// User or Auto IV & No HMAC
				testingRun.decryptBothIV(true, inputFilepath, inputKey, false);
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	private void testStringDecryption(boolean usingHMAC, String inputCiphertextBase64, String inputKey)
	{
		try {
			if (usingHMAC) {
				// User or Auto IV & HMAC
				System.out.println(testingRun.decryptBothIV(false, inputCiphertextBase64, inputKey, true));
			}
			else {
				// User or Auto IV & No HMAC
				System.out.println(testingRun.decryptBothIV(false, inputCiphertextBase64, inputKey, false));
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
}
