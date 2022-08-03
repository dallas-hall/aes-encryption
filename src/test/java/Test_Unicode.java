/**
 * Created by dhall on 6/06/2017.
 */
public class Test_Unicode
{
	private static byte[] bytesArray = {'\u0044', '\u0041', '\u004c', '\u004c', '\u0041', '\u0053', '\u0020', '\u0048', '\u0041', '\u004c', '\u004c', '\u002e', '\u002e', '\u002e', '\u002e', '\u002e'};
	private static String s = "DALLAS HALL.....";

	public static void main(String[] args) throws Exception
	{
		Test_Unicode run1 = new Test_Unicode();
	}

	private String getUnicodeValue(char inputChar)
	{
		return "\\u" + Integer.toHexString(inputChar | 0x10000).substring(1);
	}

	public Test_Unicode() throws Exception
	{
		for (int i = 0; i < bytesArray.length; i++) {
			System.out.print(((char) bytesArray[i]));
		}
		System.out.println();

		char[] charArray = s.toCharArray();
		for (int i = 0; i < bytesArray.length; i++) {
			System.out.print(getUnicodeValue(charArray[i]) + " ");
		}
		System.out.println();

		for (char b : charArray) {
			System.out.print(b);
		}
		System.out.println();

		for (byte b : bytesArray) {
			System.out.print(getUnicodeValue(((char) b)) + " ");
		}
	}
}
