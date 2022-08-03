import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;

/**
 * <h1>Encryption and Decryption Testing</h1>
 * <p>
 * This program will test the AES CBC No Padding algorithm using 128bit, 192bit, and 256bit modes on the Known Answer Tests (KAT).
 * </p>
 * <p>
 * tags:	AES; CBC; PKCS5 Padding; NIST KAT;
 * </p>
 *
 * @author dhall
 * @version 0.1 - 2017-05-18
 */
public class Test_AES_KAT_MMT
{
	//INSTANCE VARIABLES
	private static final String CIPHER_ALGORITHM = "AES";
	private static final String CIPHER_ALGORITHM_MODE_PADDING = "AES/CBC/PKCS5PADDING";
	private static final String CIPHER_ALGORITHM_MODE_NOPADDING = "AES/CBC/NoPadding";
	private int testCounter = 0;

	//MAIN METHOD
	public static void main(String[] args)
	{
		Test_AES_KAT_MMT run1 = new Test_AES_KAT_MMT();
	}

	//CONSTRUCTOR(S)
	public Test_AES_KAT_MMT()
	{
		System.out.println("\n##################");
		System.out.println("# AES 128bit Key #");
		System.out.println("##################\n");
		System.out.println("**************");
		System.out.println("* Encryption *");
		System.out.println("**************\n");
		//TEST 1
		System.out.println("Test " + testCounter++);
		//input variables
		String katSecretKeyBase16 = "1f8e4973953f3fb0bd6b16662e9a3c17";
		String katIvBase16 = "2fe2b333ceda8f98f4a99b40d2cd34a8";
		String katPlaintextBase16 = "45cf12964fc824ab76616ae2f4bf0822";
		String katCiphertextBase16 = "0f61c4d44c5147c03c195ad7e2cc12b2";

		//output variables
		String computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		String computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 2
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "0700d603a1c514e46b6191ba430a3a0c";
		katIvBase16 = "aad1583cd91365e3bb2f0c3430d065bb";
		katPlaintextBase16 = "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91";
		katCiphertextBase16 = "c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 3
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "b7f3c9576e12dd0db63e8f8fac2b9a39";
		katIvBase16 = "c80f095d8bb1a060699f7c19974a1aa0";
		katPlaintextBase16 = "9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e";
		katCiphertextBase16 = "19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 4
		System.out.println("Test " + testCounter++);
		//input variables
		//input variables
		katSecretKeyBase16 = "b6f9afbfe5a1562bba1368fc72ac9d9c";
		katIvBase16 = "3f9d5ebe250ee7ce384b0d00ee849322";
		katPlaintextBase16 = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
		katCiphertextBase16 = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 5
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "bbe7b7ba07124ff1ae7c3416fe8b465e";
		katIvBase16 = "7f65b5ee3630bed6b84202d97fb97a1e";
		katPlaintextBase16 = "2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd9110914011b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5f78f31ff7caf187";
		katCiphertextBase16 = "3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff5661a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60a70e0074fc11efe";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//reset variables for next tests
		testCounter = 0;
		katSecretKeyBase16 = null;
		katIvBase16 = null;
		katPlaintextBase16 = null;
		katCiphertextBase16 = null;
		computedCiphertext = null;
		computedPlaintext = null;

		System.out.println("\n***************");
		System.out.println("* Deccryption *");
		System.out.println("***************\n");
		;

		//TEST 1
		//input variables
		katSecretKeyBase16 = "6a7082cf8cda13eff48c8158dda206ae";
		katIvBase16 = "bd4172934078c2011cb1f31cffaf486e";
		katCiphertextBase16 = "f8eb31b31e374e960030cd1cadb0ef0c";
		katPlaintextBase16 = "940bc76d61e2c49dddd5df7f37fcf105";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 2
		//input variables
		katSecretKeyBase16 = "625eefa18a4756454e218d8bfed56e36";
		katIvBase16 = "73d9d0e27c2ec568fbc11f6a0998d7c8";
		katCiphertextBase16 = "5d6fed86f0c4fe59a078d6361a142812514b295dc62ff5d608a42ea37614e6a1";
		katPlaintextBase16 = "360dc1896ce601dfb2a949250067aad96737847a4580ede2654a329b842fe81e";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 3
		//input variables
		katSecretKeyBase16 = "fd6e0b954ae2e3b723d6c9fcae6ab09b";
		katIvBase16 = "f08b65c9f4dd950039941da2e8058c4e";
		katCiphertextBase16 = "e29e3114c8000eb484395b256b1b3267894f290d3999819ff35da03e6463c186c4d7ebb964941f1986a2d69572fcaba8";
		katPlaintextBase16 = "a206385945b21f812a9475f47fddbb7fbdda958a8d14c0dbcdaec36e8b28f1f6ececa1ceae4ce17721d162c1d42a66c1";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 4
		//input variables
		katSecretKeyBase16 = "7b1ab9144b0239315cd5eec6c75663bd";
		katIvBase16 = "0b1e74f45c17ff304d99c059ce5cde09";
		katCiphertextBase16 = "d3f89b71e033070f9d7516a6cb4ea5ef51d6fb63d4f0fea089d0a60e47bbb3c2e10e9ba3b282c7cb79aefe3068ce228377c21a58fe5a0f8883d0dbd3d096beca";
		katPlaintextBase16 = "b968aeb199ad6b3c8e01f26c2edad444538c78bfa36ed68ca76123b8cdce615a01f6112bb80bfc3f17490578fb1f909a52e162637b062db04efee291a1f1af60";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 5
		//input variables
		katSecretKeyBase16 = "36466b6bd25ea3857ea42f0cac1919b1";
		katIvBase16 = "7186fb6bdfa98a16189544b228f3bcd3";
		katCiphertextBase16 = "9ed957bd9bc52bba76f68cfbcde52157a8ca4f71ac050a3d92bdebbfd7c78316b4c9f0ba509fad0235fdafe90056ad115dfdbf08338b2acb1c807a88182dd2a882d1810d4302d598454e34ef2b23687d";
		katPlaintextBase16 = "999983467c47bb1d66d7327ab5c58f61ddb09b93bd2460cb78cbc12b5fa1ea0c5f759ccc5e478697687012ff4673f6e61eecaeda0ccad2d674d3098c7d17f887b62b56f56b03b4d055bf3a4460e83efa";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		// ### 196bit key test ###
		System.out.println("\n##################");
		System.out.println("# AES 196bit Key #");
		System.out.println("##################\n");
		System.out.println("**************");
		System.out.println("* Encryption *");
		System.out.println("**************\n");
		//reset variables for next tests
		testCounter = 0;
		katSecretKeyBase16 = null;
		katIvBase16 = null;
		katPlaintextBase16 = null;
		katCiphertextBase16 = null;
		computedCiphertext = null;
		computedPlaintext = null;

		//TEST 1
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c";
		katIvBase16 = "531ce78176401666aa30db94ec4a30eb";
		katPlaintextBase16 = "c51fc276774dad94bcdc1d2891ec8668";
		katCiphertextBase16 = "70dd95a14ee975e239df36ff4aee1d5d";

		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 2
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "eab3b19c581aa873e1981c83ab8d83bbf8025111fb2e6b21";
		katIvBase16 = "f3d6667e8d4d791e60f7505ba383eb05";
		katPlaintextBase16 = "9d4e4cccd1682321856df069e3f1c6fa391a083a9fb02d59db74c14081b3acc4";
		katCiphertextBase16 = "51d44779f90d40a80048276c035cb49ca2a47bcb9b9cf7270b9144793787d53f";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 3
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "16c93bb398f1fc0cf6d68fc7a5673cdf431fa147852b4a2d";
		katIvBase16 = "eaaeca2e07ddedf562f94df63f0a650f";
		katPlaintextBase16 = "c5ce958613bf741718c17444484ebaf1050ddcacb59b9590178cbe69d7ad7919608cb03af13bbe04f3506b718a301ea0";
		katCiphertextBase16 = "ed6a50e0c6921d52d6647f75d67b4fd56ace1fedb8b5a6a997b4d131640547d22c5d884a75e6752b5846b5b33a5181f4";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 4
		System.out.println("Test " + testCounter++);
		//input variables
		//input variables
		katSecretKeyBase16 = "067bb17b4df785697eaccf961f98e212cb75e6797ce935cb";
		katIvBase16 = "8b59c9209c529ca8391c9fc0ce033c38";
		katPlaintextBase16 = "db3785a889b4bd387754da222f0e4c2d2bfe0d79e05bc910fba941beea30f1239eacf0068f4619ec01c368e986fca6b7c58e490579d29611bd10087986eff54f";
		katCiphertextBase16 = "d5f5589760bf9c762228fde236de1fa2dd2dad448db3fa9be0c4196efd46a35c84dd1ac77d9db58c95918cb317a6430a08d2fb6a8e8b0f1c9b72c7a344dc349f";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 5
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "0fd39de83e0be77a79c8a4a612e3dd9c8aae2ce35e7a2bf8";
		katIvBase16 = "7e1d629b84f93b079be51f9a5f5cb23c";
		katPlaintextBase16 = "38fbda37e28fa86d9d83a4345e419dea95d28c7818ff25925db6ac3aedaf0a86154e20a4dfcc5b1b4192895393e5eb5846c88bdbd41ecf7af3104f410eaee470f5d9017ed460475f626953035a13db1f";
		katCiphertextBase16 = "edadae2f9a45ff3473e02d904c94d94a30a4d92da4deb6bcb4b0774472694571842039f21c496ef93fd658842c735f8a81fcd0aa578442ab893b18f606aed1bab11f81452dd45e9b56adf2eccf4ea095";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//reset variables for next tests
		//reset variables for next tests
		testCounter = 0;
		katSecretKeyBase16 = null;
		katIvBase16 = null;
		katPlaintextBase16 = null;
		katCiphertextBase16 = null;
		computedCiphertext = null;
		computedPlaintext = null;

		System.out.println("\n***************");
		System.out.println("* Deccryption *");
		System.out.println("***************\n");
		;

		//TEST 1
		//input variables
		katSecretKeyBase16 = "8e2740fba157aef2422e442312d15c14d312553684fcdc15";
		katIvBase16 = "324015878cdc82bfae59a2dc1ff34ea6";
		katCiphertextBase16 = "39a9b42de19e512ab7f3043564c3515a";
		katPlaintextBase16 = "aa41179d880e6fe3b14818d6e4a62eb5";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 2
		//input variables
		katSecretKeyBase16 = "0ac0d2add273d1a260c432c662b4be4d8d366edc3f402e40";
		katIvBase16 = "0cc3744fa9cef13fe04a5ab6ac9b8de4";
		katCiphertextBase16 = "2cd57dce7465d5ecde153e87ce45e62286c6b023a446dae3ec0fdc0648f29308";
		katPlaintextBase16 = "854e97e19b5c4fbd7a2ac7f8ddccdc8eac1a166832b58f05ae5088d7caba8fee";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 3
		//input variables
		katSecretKeyBase16 = "3915d786c786731cfe35abe39fac714f5fa32c7ef3c6681b";
		katIvBase16 = "a2d326a8226576e32e48f62b3da96c40";
		katCiphertextBase16 = "a9968021d6df78ff2c4c236bdd9a55bc727b0dc506f44958b2041f0948860a3444588242ffbdcf2726001e2f6b5bd5fb";
		katPlaintextBase16 = "4a7a4dca5c555d3f0358be7db4af14f1322a8861a3cb977f029fdcbd8ee4a8d451f32d7865e6a2376edf67e4d1092e15";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 4
		//input variables
		katSecretKeyBase16 = "92317d4d38168a359118a0df0b7b45cbfdcc2011e7175d3c";
		katIvBase16 = "75be95a6a54400b2e1b485e24ead18ed";
		katCiphertextBase16 = "f67581763d23326f699e05696043b4c553928c2a9f857377f12029fcae4acee992dba50697f617a51899fbd6367214d97bf5dbd9bdab7fd745cd2be431118793";
		katPlaintextBase16 = "7b88fb0195a57ac61ccb3198a05517717523444da92d2e8c37840a7f7614c9effa6dd6f1d1a730ec350cd64b99738cfb3b962c791b2674929f936e894cbcb994";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 5
		//input variables
		katSecretKeyBase16 = "cd00048ce8ead5b5dff2346a86eac594b2a4194ca99fc89f";
		katIvBase16 = "154cb1d42ad9e8d85ebb0b5189b6e1bc";
		katCiphertextBase16 = "a12b32199ae6484418ac7097fda9bb33f2ae421dfd795c9b553615e17546dcec6f3e7caf83334e6df035ac660a19a8b58d7cfe79310448337ee9716fe2b46ca7014726644c1eb9a6d5d4e28661e9b51a";
		katPlaintextBase16 = "07d471fa87fb5f267346aa4956c8bdb6c95493b1c19be8ca09deffd690d57463229352faf2878bc66a20f199d9f6b2378e6073c2cef002c628ce94d1adb5539bd15c4a51156f98f52bbe90a1905d35de";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		// ### 256bit key test ###
		// ### 196bit key test ###
		System.out.println("\n##################");
		System.out.println("# AES 256bit Key #");
		System.out.println("##################\n");
		System.out.println("**************");
		System.out.println("* Encryption *");
		System.out.println("**************\n");
		//reset variables for next tests
		testCounter = 0;
		katSecretKeyBase16 = null;
		katIvBase16 = null;
		katPlaintextBase16 = null;
		katCiphertextBase16 = null;
		computedCiphertext = null;
		computedPlaintext = null;

		//TEST 1
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907";
		katIvBase16 = "851e8764776e6796aab722dbb644ace8";
		katPlaintextBase16 = "6282b8c05c5c1530b97d4816ca434762";
		katCiphertextBase16 = "6acc04142e100a65f51b97adf5172c41";

		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 2
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "dce26c6b4cfb286510da4eecd2cffe6cdf430f33db9b5f77b460679bd49d13ae";
		katIvBase16 = "fdeaa134c8d7379d457175fd1a57d3fc";
		katPlaintextBase16 = "50e9eee1ac528009e8cbcd356975881f957254b13f91d7c6662d10312052eb00";
		katCiphertextBase16 = "2fa0df722a9fd3b64cb18fb2b3db55ff2267422757289413f8f657507412a64c";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 3
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5";
		katIvBase16 = "c0cd2bebccbb6c49920bd5482ac756e8";
		katPlaintextBase16 = "8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c";
		katCiphertextBase16 = "05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 4
		System.out.println("Test " + testCounter++);
		//input variables
		//input variables
		katSecretKeyBase16 = "9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85";
		katIvBase16 = "11958dc6ab81e1c7f01631e9944e620f";
		katPlaintextBase16 = "c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf53e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3052d8b21c5561c8b660e";
		katCiphertextBase16 = "9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832ccdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc557e2b45b49ce05511e65";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 5
		System.out.println("Test " + testCounter++);
		//input variables
		katSecretKeyBase16 = "9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85";
		katIvBase16 = "11958dc6ab81e1c7f01631e9944e620f";
		katPlaintextBase16 = "c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf53e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3052d8b21c5561c8b660e";
		katCiphertextBase16 = "9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832ccdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc557e2b45b49ce05511e65";
		//output variables
		computedCiphertext = encrypt(katPlaintextBase16, katSecretKeyBase16, katIvBase16);
		computedPlaintext = decrypt(computedCiphertext, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Expected ciphertext:\t" + katCiphertextBase16);
		System.out.println("Computed ciphertext:\t" + computedCiphertext);
		System.out.println("Do they match?\t\t\t" + katCiphertextBase16.equals(computedCiphertext) + "\n");
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//reset variables for next tests
		//reset variables for next tests
		testCounter = 0;
		katSecretKeyBase16 = null;
		katIvBase16 = null;
		katPlaintextBase16 = null;
		katCiphertextBase16 = null;
		computedCiphertext = null;
		computedPlaintext = null;

		System.out.println("\n***************");
		System.out.println("* Deccryption *");
		System.out.println("***************\n");
		;

		//TEST 1
		//input variables
		katSecretKeyBase16 = "43e953b2aea08a3ad52d182f58c72b9c60fbe4a9ca46a3cb89e3863845e22c9e";
		katIvBase16 = "ddbbb0173f1e2deb2394a62aa2a0240e";
		katCiphertextBase16 = "d51d19ded5ca4ae14b2b20b027ffb020";
		katPlaintextBase16 = "07270d0e63aa36daed8c6ade13ac1af1";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 2
		//input variables
		katSecretKeyBase16 = "addf88c1ab997eb58c0455288c3a4fa320ada8c18a69cc90aa99c73b174dfde6";
		katIvBase16 = "60cc50e0887532e0d4f3d2f20c3c5d58";
		katCiphertextBase16 = "6cb4e2f4ddf79a8e08c96c7f4040e8a83266c07fc88dd0074ee25b00d445985a";
		katPlaintextBase16 = "98a8a9d84356bf403a9ccc384a06fe043dfeecb89e59ce0cb8bd0a495ef76cf0";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 3
		//input variables
		katSecretKeyBase16 = "54682728db5035eb04b79645c64a95606abb6ba392b6633d79173c027c5acf77";
		katIvBase16 = "2eb94297772851963dd39a1eb95d438f";
		katCiphertextBase16 = "e4046d05385ab789c6a72866e08350f93f583e2a005ca0faecc32b5cfc323d461c76c107307654db5566a5bd693e227c";
		katPlaintextBase16 = "0faa5d01b9afad3bb519575daaf4c60a5ed4ca2ba20c625bc4f08799addcf89d19796d1eff0bd790c622dc22c1094ec7";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 4
		//input variables
		katSecretKeyBase16 = "7482c47004aef406115ca5fd499788d582efc0b29dc9e951b1f959406693a54f";
		katIvBase16 = "485ebf2215d20b816ea53944829717ce";
		katCiphertextBase16 = "6c24f19b9c0b18d7126bf68090cb8ae72db3ca7eabb594f506aae7a2493e5326a5afae4ec4d109375b56e2b6ff4c9cf639e72c63dc8114c796df95b3c6b62021";
		katPlaintextBase16 = "82fec664466d585023821c2e39a0c43345669a41244d05018a23d7159515f8ff4d88b01cd0eb83070d0077e065d74d7373816b61505718f8d4f270286a59d45e";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");

		//TEST 5
		//input variables
		katSecretKeyBase16 = "3ae38d4ebf7e7f6dc0a1e31e5efa7ca123fdc321e533e79fedd5132c5999ef5b";
		katIvBase16 = "36d55dc9edf8669beecd9a2a029092b9";
		katCiphertextBase16 = "d50ea48c8962962f7c3d301fa9f877245026c204a7771292cddca1e7ffebbef00e86d72910b7d8a756dfb45c9f1040978bb748ca537edd90b670ecee375e15d98582b9f93b6355adc9f80f4fb2108fb9";
		katPlaintextBase16 = "8d22db30c4253c3e3add9685c14d55b05f7cf7626c52cccfcbe9b99fd8913663b8b1f22e277a4cc3d0e7e978a34782eb876867556ad4728486d5e890ea738243e3700a696d6eb58cd81c0e60eb121c50";
		//output variables
		computedPlaintext = decrypt(katCiphertextBase16, katSecretKeyBase16, katIvBase16);
		//test run
		System.out.println("Test " + testCounter++);
		System.out.println("Original plaintext:\t\t" + katPlaintextBase16);
		System.out.println("Decrypted plaintext:\t" + computedPlaintext);
		System.out.println("Do they match?\t\t\t" + katPlaintextBase16.equals(computedPlaintext) + "\n");
	}

	//METHODS
	// https://stackoverflow.com/questions/8890174/in-java-how-do-i-convert-a-hex-string-to-a-byte/19119453#19119453
	public static byte[] hexStringToByteArray(String inputStringBase16)
	{
		int len = inputStringBase16.length();
		byte[] dataBytesBase2 = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			dataBytesBase2[i / 2] = (byte) ((Character.digit(inputStringBase16.charAt(i), 16) << 4) + Character.digit(inputStringBase16.charAt(i + 1), 16));
		}
		return dataBytesBase2;
	}

	/**
	 * This method is use for the MMT and KAT tests
	 *
	 * @param inputStringBase16 - the hexadecimal string used as input
	 * @return - the string in binary
	 */
	private String hexToBinary(String inputStringBase16)
	{
		//Use a BigInteger so we can store arbitrarily large numbers.  Radix 16 = hex, radix 2 = binary
		return new BigInteger(inputStringBase16, 16).toString(2);
	}

	private String encrypt(String inputPlaintextBase16, String inputKeyBase16, String inputIvBase16)
	{
		try {
			// JAVA Cryptography
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Introduction

			// 16 BYTE (128 BIT) KEY or 24 BYTE (196 BIT) KEY or 32 BYTES (256 BIT) KEY
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/SecretKeySpec.html
			SecretKeySpec secretKey = new SecretKeySpec(hexStringToByteArray(inputKeyBase16), CIPHER_ALGORITHM);

			// 16 BYTE (128 BIT) INITIALISATION VECTOR
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/IvParameterSpec.html
			// generate garbage IV
			byte[] ivBytesArrayBase2 = hexStringToByteArray(inputIvBase16);
			IvParameterSpec iv = iv = new IvParameterSpec(ivBytesArrayBase2);

			// CRYPTORGAPY CIPHER
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
			// https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_MODE_NOPADDING);

			// ENCRYPTION PHASE
			// https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html#init(int,%20java.security.Key,%20java.security.SecureRandom)
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
			byte[] ciphertextBytesBase2 = cipher.doFinal(hexStringToByteArray(inputPlaintextBase16));

			// CONVERT BINARY TO BASE64 / BASE16
			// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
			String ciphertextBase16 = new String(DatatypeConverter.printHexBinary(ciphertextBytesBase2).toLowerCase());
			return ciphertextBase16;


		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	/**
	 * This method is used to read in a String that is encrypted with AES 128 CBC PCKS#5 Padding.
	 * The String is decrypted it via the supplied secret key and the prepended IV.
	 *
	 * @param inputCiphertextBase16 - this it user supplied ciphertext to be decrypted, usually in Base64, can be Base16
	 * @param inputKeyBase16        - this is the user supplied secret key
	 * @param inputIvBase16         - this is only used to do the KAT decrypt tests.
	 * @return - this is the plaintext returned after decryption
	 */
	private String decrypt(String inputCiphertextBase16, String inputKeyBase16, String inputIvBase16)
	{
		try {
			String ciphertextBase64 = null;
			// KEY
			SecretKeySpec secretKey = new SecretKeySpec(hexStringToByteArray(inputKeyBase16), CIPHER_ALGORITHM);

			// INITIALISATION VECTOR
			//convert the IV back to a bytes
			byte[] ivBytesBase2 = hexStringToByteArray(inputIvBase16);
			// recreate IV
			IvParameterSpec iv = new IvParameterSpec(ivBytesBase2);

			// CRYPTORGAPY CIPHER
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_MODE_NOPADDING);

			// DECRYPTION PHASE
			//convert hex to binary
			byte[] ciphertextBytesBase2 = hexStringToByteArray(inputCiphertextBase16);
			//decrypt stuff
			cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
			byte[] plaintextBytesBase2 = cipher.doFinal(ciphertextBytesBase2);

			// OUTPUT
			return new String(DatatypeConverter.printHexBinary(plaintextBytesBase2).toLowerCase());
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
}
