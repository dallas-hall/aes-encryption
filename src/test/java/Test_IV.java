import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Created by dhall on 17/05/2017.
 */
public class Test_IV
{
	public static void main(String[] args)
	{
		Test_IV run1 = new Test_IV();
	}

	public Test_IV()
	{
		System.out.println("Base64 IV: " + createIV() + " & the length is " + createIV().length());
		String blah = "8R+JymhyPbRqCWSxLEUuyQ==THIS IS THE BIT THAT I DON'T WANT!!!!";
		String bleh = "8R+JymhyPbRqCWSxLEUuyQ==";
		System.out.println(blah);
		System.out.println(blah.substring(0, bleh.length()));
		System.out.println(blah.substring(bleh.length()));
	}

	public String createIV()
	{
		// INITIALISATION VECTOR
		// create a cryptograhpically strong 16 byte pseudo-random number via the pseudo-random number generator (PRNG).
		// https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html
		SecureRandom random = new SecureRandom();
		//get a random series of 16 bytes and use this as the IV
		byte[] ivBytes = new byte[16];
		random.nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		String base64IV = new String(Base64.getEncoder().encode(ivBytes));
		return base64IV;
	}
}
