import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Created by dhall on 18/05/2017.
 */
public class Test_HMAC
{

	private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");
	private static final Charset CHARSET_ASCII = Charset.forName("US-ASCII");
	private static final String HMAC_MODE = "HmacSHA512";

	public static void main(String[] args)
	{
		Test_HMAC run1 = new Test_HMAC();
	}

	public Test_HMAC()
	{
		String data;
		String data2;
		String hmac;
		String hmac2;
		try {
			data = readFile("src/main/resources/I can eat glass.txt", CHARSET_UTF8);
			data2 = readFile("src/main/resources/Linux 101 Chapter Summaries.txt", CHARSET_UTF8);
			hmac = getHMAC(data, "0123456789ABCDEF");
			hmac2 = getHMAC(data2, "0123456789ABCDEF");
			System.out.println("SHA512 HMAC 1 in Base64: " + hmac);
			System.out.println("The length is " + hmac.length());
			System.out.println("SHA512 HMAC 2 in Base64: " + hmac2);
			System.out.println("The length is " + hmac2.length());
		}
		catch (Exception e) {
			//System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}

	private String getHMAC(String inputData, String inputKey) throws Exception
	{
		//create MAC object
		Mac hmacSHA512 = Mac.getInstance(HMAC_MODE);
		//create Key object
		SecretKeySpec secretKey = new SecretKeySpec(inputKey.getBytes(CHARSET_UTF8), HMAC_MODE);
		//hash stuff
		hmacSHA512.init(secretKey);
		String finalHMAC = new String(Base64.getEncoder().encode(hmacSHA512.doFinal(inputData.getBytes(CHARSET_UTF8))));
		return finalHMAC;
	}

	private String readFile(String path, Charset encoding) throws IOException
	{
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}
}
