/**
 * <h1>Encryption and Decryption Testing</h1>
 * <p>
 * This program will test the AES CBC PCKS5 Padding algorithm using 128bit, 192bit, and 256bit modes on Strings.
 * </p>
 * <p>
 * tags:	AES; CBC; PKCS5 Padding;
 * </p>
 *
 * @author dhall
 * @version 0.1 - 2018-03-23
 */
public class Test_Encrypt_And_Decrypt
{
	//@@@ MAIN METHOD @@@
	public static void main(String[] args)
	{
		// Setup
		AES_CBC_Padding_Encrypt encryptRuntime = new AES_CBC_Padding_Encrypt();
		AES_CBC_Padding_Decrypt decryptRuntime = new AES_CBC_Padding_Decrypt();

		String[] ciphertext = new String[3];
		String[] cipherMode = {"AES128", "AES192", "AES256"};
		String[] passwords = {"0123456789ABCDEF", "0123456789ABCDEF01234567", "0123456789ABCDEF0123456789ABCDEF"};
		String[] plaintext = new String[3];
		String originalText = "This the text that you are not allowed to see my friend. Go away!";

		// Testing
		System.out.println("@@@ AES CBC Padding Testing @@@");
		System.out.println("### Encryption Round ###");
		for (int i = 0; i < passwords.length; i++) {
			ciphertext[i] = encryptRuntime.encrypt(originalText, passwords[i]);
			System.out.println(cipherMode[i] + " - The ciphertext is " + ciphertext[i]);
		}

		System.out.println("\n### Decryption Round ###");
		for (int i = 0; i < passwords.length; i++) {
			plaintext[i] = decryptRuntime.decrypt(ciphertext[i], passwords[i]);
			System.out.println(cipherMode[i] + " - The plaintext is: " + plaintext[i]);
		}
	}
}

