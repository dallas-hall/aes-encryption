import org.apache.commons.cli.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <h1>AES CBC Padding CLI Program</h1>
 * <p>
 * This program performs AES 128, 192, or 256 encryption using CBC and PKCS#5 padding.
 * </p>
 *
 * @author dhall
 * @version 0.1 - 2018-02-23
 */
public class CLI
{
	//@@@ INSTANCE VARIABLES @@@
	private static boolean debugging = false;
	private static final String PROGRAM_NAME = "AES CBC PKCS5 Padding CLI";
	private static final String PROGRAM_VERSION_MAJOR = "1";
	private static final String PROGRAM_VERSION_MINOR = "4";
	private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
	private static final DateFormat TIME_FORMAT = new SimpleDateFormat("HH-mm-ss");
	private static final String OUTPUT_PATH = System.getProperty("user.dir") + "/";

	// Licence & help information
	private static final String LICENCE = "### MIT License ###\n" + "Copyright (c) 2018 Dallas Hall\n\n" + "Permission is hereby granted, free of charge, to any person obtaining a copy\n" + "of this software and associated documentation files (the \"Software\"), to deal\n" + "in the Software without restriction, including without limitation the rights\n" + "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n" + "copies of the Software, and to permit persons to whom the Software is\n" + "furnished to do so, subject to the following conditions:\n" + "\n" + "The above copyright notice and this permission notice shall be included in all\n" + "copies or substantial portions of the Software.\n" + "\n" + "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n" + "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n" + "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n" + "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n" + "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n" + "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n" + "SOFTWARE.";
	private static final String HELP_MESSAGE = "### Program Help ###.\n" + "This is the help message for the AES CBC Padding CLI program. This will perform AES encryption and decryption using CBC mode and PKCS5 padding mode. It will print and return a UTF-8 encoded String.\n\n" + "Usage: java -jar AES_CBC_Padding_CLI.jar argument(s)\n" + "The following are valid arguments.\n" + "\n-d --decrypt\t\tUse decryption cipher mode.\n" + "-e --encrypt\t\tUse encryption cipher mode.\n" + "-f --files\t\tUse a file for encryption or decryption.\n" + "-h --help\t\tDisplay this message.\n" + "-k --key\t\tTo enter your private key. Must be 16, 24, or 32 characters. 16 = AES 128, 24 = AES 192, 32 = AES 256.\n" + "-l --licence\t\tDisplay the program licence and author information.\n" + "-t --text\t\tUse text for encryption or decryption. Text with spaces must be \"wrapped in double quotes.\" The quotes will not be added.\n" + "-v --verbose-off\tOnly display and return the final output. Useful when integrating with other scripts." + "\nNote: options d/e and f/t are interchangeable (i.e. use one or the other).\n" + "\nHere are some usage examples.\n" + "Encrypt text using AES 128:\t\tjava -jar AES_CBC_Padding-" + PROGRAM_VERSION_MAJOR + "." + PROGRAM_VERSION_MINOR + ".jar -e -t \"my text to encrypt\" -k 0123456789ABCDEF\n" + "Decrypt text using AES 128:\t\tjava -jar AES_CBC_Padding-" + PROGRAM_VERSION_MAJOR + "." + PROGRAM_VERSION_MINOR + ".jar -d -t 7fOYYU86m241SClZ+b6LZQ==VL4gPKI4hbXiczKC6wAG6DNMjBbEcAGI+kDeBO3l2Cs= -k 0123456789ABCDEF\n" + "Encrypt a file using AES 128:\t\tjava -jar AES_CBC_Padding-" + PROGRAM_VERSION_MAJOR + "." + PROGRAM_VERSION_MINOR + ".jar -e -f relative/path/to/file -k 0123456789ABCDEF\n" + "Decrypt a file using AES 128:\t\tjava -jar AES_CBC_Padding-" + PROGRAM_VERSION_MAJOR + "." + PROGRAM_VERSION_MINOR + ".jar -d -f /absolute/path/to/file -k 0123456789ABCDEF\n" + "Encrypt in a program using AES 128:\tjava -jar AES_CBC_Padding-" + PROGRAM_VERSION_MAJOR + "." + PROGRAM_VERSION_MINOR + ".jar -e -t aVariable -k 0123456789ABCDEF -v\n" + "Decrypt in a program using AES 128:\tjava -jar AES_CBC_Padding-" + PROGRAM_VERSION_MAJOR + "." + PROGRAM_VERSION_MINOR + ".jar -d -t $another_variable -k 0123456789ABCDEF -v\n";

	// Encryption Stuff
	private static AES_CBC_Padding_Encrypt encryptionCipher = new AES_CBC_Padding_Encrypt();
	private static AES_CBC_Padding_Decrypt decryptionCipher = new AES_CBC_Padding_Decrypt();


	//@@@ MAIN METHOD @@@
	public static void main(String[] args) throws ParseException
	{
		if (debugging) {
			for (int i = 0; i < args.length; i++) {
				System.out.println("args index " + i + " = " + args[i]);
			}
		}

		// Program Local Variables
		String privateKey = null;
		String inputText = null;
		boolean useFile = false;
		boolean useDecrypt = false;
		boolean verboseModeOn = true;
		String inputPath = null;
		StringBuilder aStringBuilder = new StringBuilder();

		// Setup Program Commands - https://commons.apache.org/proper/commons-cli/usage.html
		if (args.length == 1 || args.length == 5 || args.length == 6) {
			try {
				// Setup Arguments
				Options cliOptions = new Options();
				cliOptions.addOption("d", "decrypt", false, "Decryption cipher mode.");
				cliOptions.addOption("e", "encrypt", false, "Encryption cipher mode.");
				cliOptions.addOption("f", "file", true, "The source file, can be an absolute or relative path.");
				cliOptions.addOption("h", "help", false, "Display this help message.");
				cliOptions.addOption("k", "key", true, "The private key.");
				cliOptions.addOption("l", "licence", false, "Display this licence message.");
				cliOptions.addOption("t", "text", true, "The source text. Text with spaces must be \"wrapped in double quotes.\"");
				cliOptions.addOption("v", "verbose-off", false, "Turns off all program output, except for the final output.");

				// Setup Argument Parser
				CommandLineParser commandLineParser = new DefaultParser();
				CommandLine commandLine = commandLineParser.parse(cliOptions, args);

				// Parse Argument(s)
				if (commandLine.hasOption("v") || commandLine.hasOption("verbose-off")) {
					verboseModeOn = false;
				}
				if (verboseModeOn) {
					System.out.println("@@@ " + PROGRAM_NAME + " @@@");
				}

				if (commandLine.hasOption("h") || commandLine.hasOption("help")) {
					System.out.println(HELP_MESSAGE);
					System.exit(0);
				}
				else if (commandLine.hasOption("l") || commandLine.hasOption("licence")) {
					System.out.println(LICENCE);
					System.exit(0);

				}

				if (verboseModeOn) {
					System.out.println("### Program Mode ###");
				}
				if (commandLine.hasOption("d") || commandLine.hasOption("decrypt")) {
					if (verboseModeOn) {
						System.out.println("DECRYPTION mode activated.");
					}
					useDecrypt = true;
				}
				else if (commandLine.hasOption("e") || commandLine.hasOption("encrypt")) {
					if (verboseModeOn) {
						System.out.println("ENCRYPTION mode activated");
					}
					useDecrypt = false;
				}

				if (commandLine.hasOption("f") || commandLine.hasOption("file")) {
					if (verboseModeOn) {
						System.out.println("Sourcing data from the supplied file path.");
					}
					useFile = true;
					// Get the path
					if (commandLine.hasOption("f")) {
						inputPath = commandLine.getOptionValue("f");
					}
					if (commandLine.hasOption("file")) {
						inputPath = commandLine.getOptionValue("file");
					}
				}
				else if (commandLine.hasOption("t") || commandLine.hasOption("text")) {
					if (verboseModeOn) {
						System.out.println("Sourcing data from the supplied text.");
					}
					// Get the text
					if (commandLine.hasOption("t")) {
						inputText = commandLine.getOptionValue("t");
					}
					if (commandLine.hasOption("text")) {
						inputText = commandLine.getOptionValue("text");
					}
					if (debugging) {
						System.out.println("The supplied text was: " + inputText);
					}
				}


				try {
					if ((commandLine.hasOption("k") || commandLine.hasOption("key"))) {
						// Get the key
						if (commandLine.hasOption("k")) {
							privateKey = commandLine.getOptionValue("k");
						}
						if (commandLine.hasOption("key")) {
							privateKey = commandLine.getOptionValue("key");
						}
						if (debugging) {
							System.out.println("Your private key is: " + privateKey);
							System.out.println("Private key length is: " + privateKey.length());
						}

						int privateKeyLength = privateKey.length();
						if (privateKeyLength == 16 || privateKeyLength == 24 || privateKeyLength == 32) {
						}
						else {
							throw new ParseException("Invalid key length, must be 16, 24, or 32 characters long.\nYour key is currently " + privateKeyLength + ".");
						}

					}
				}
				catch (ParseException e) {
					System.out.println(e.getMessage());
					System.exit(1);
				}

				if (commandLine.hasOption("l") || commandLine.hasOption("licence")) {
					System.out.println(LICENCE);

				}

			}
			catch (UnrecognizedOptionException e) {
				System.out.println("Invalid arguments supplied. Please run the program with -h or --help for a list of valid arguments.");
				System.exit(1);
			}
		}
		else {
			System.out.println("Invalid arguments supplied. Please run the program with -h or --help for a list of valid arguments.");
			System.exit(1);
		}

		if (verboseModeOn) {
			System.out.println("\n### Processing ###");
		}
		if (useFile && useDecrypt) {
			String outputPath = decryptFile(inputPath, privateKey, verboseModeOn);
			if (debugging) {
				System.out.println("Decrypted a file from " + outputPath);
			}

		}
		else if (useFile && !useDecrypt) {
			String outputPath = encryptFile(inputPath, privateKey, verboseModeOn);
			if (debugging) {
				System.out.println("Encrypting a file from " + inputPath);
				System.out.println("Encrypted file is at " + outputPath);
			}

		}
		else if (!useFile && useDecrypt) {
			if (verboseModeOn) {
				System.out.println("Decrypting supplied text.");
			}
			decryptText(inputText, privateKey, verboseModeOn);
		}
		else if (!useFile && !useDecrypt) {
			if (verboseModeOn) {
				System.out.println("Encrypting supplied text.");
			}
			encryptText(inputText, privateKey, verboseModeOn);
		}
		else {
			System.out.println("Something went horribly wrong, abandon all hope.");
		}
	}

	//@@@ CONSTRUCTOR(S) @@@


	//@@@ METHODS @@@
	//### GETTERS ###
	private static String readFromFrom(String inputFilepath) throws IOException
	{
		//create an array of bytes, which holds the read in data from the file.  This is done 1 byte at a time, but using a buffer.
		byte[] fileBytesArrayBase2 = Files.readAllBytes(Paths.get(inputFilepath));
		//return Charset encoded human readable String of Character stream (text file)
		return new String(fileBytesArrayBase2, Charset.forName("UTF-8"));
	}

	//### SETTERS ###
	private static String decryptFile(String filePath, String privateKey, boolean verboseModeOn)
	{
		String outputText = null;
		String outputPath = null;
		try {
			String inputText = readFromFrom(filePath);
			outputText = decryptionCipher.decrypt(inputText, privateKey);
			if (debugging) {
				System.out.println("DECRYPTION - First line should be filename:\n" + outputText);
			}
			// Extract the filename and then remove it, which is stored on the first line (so 0 to the index of the first \n)
			String filename = outputText.substring(0, outputText.indexOf("\n"));
			// Remove the first line and its line break that had the filename
			outputText = outputText.substring(outputText.indexOf("\n") + 1, outputText.length());
			if (debugging) {
				System.out.println("Filename is: " + filename);
				System.out.println("Output text is: " + outputText);
			}
			outputPath = saveToFile(filename, outputText, false);
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println(outputPath);
		return outputPath;
	}

	private static String encryptFile(String filePath, String privateKey, boolean verboseModeOn)
	{
		String outputText = null;
		String outputPath = null;
		// Get the filename and add it to the plaintext for use later
		String filename = Paths.get(filePath).getFileName().toString();
		try {
			String inputText = filename + "\n" + readFromFrom(filePath);
			if (debugging) {
				System.out.println("ENCRYPTION - First line should be filename:\n" + inputText);
			}
			outputText = encryptionCipher.encrypt(inputText, privateKey);
			outputPath = saveToFile(filename, outputText, true);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println(outputPath);
		return outputPath;
	}

	private static String decryptText(String ciphertext, String privateKey, boolean verboseModeOn)
	{
		String outputText = decryptionCipher.decrypt(ciphertext, privateKey);
		if (verboseModeOn) {
			System.out.println("Your plaintext is:");
		}
		System.out.println(outputText);
		return outputText;
	}

	private static String encryptText(String plaintext, String privateKey, boolean verboseModeOn)
	{
		String outputText = encryptionCipher.encrypt(plaintext, privateKey);
		if (verboseModeOn) {
			System.out.println("Your ciphertext is:");
		}
		System.out.println(outputText);
		return outputText;
	}

	private static String saveToFile(String filename, String inputEncodedString, boolean savingCiphertext) throws IOException
	{
		String currentDate = DATE_FORMAT.format(new Date());
		String currentTime = TIME_FORMAT.format(new Date());
		//setup filename
		String dateAndTimeAndExtension = new String("@" + currentDate + "_" + currentTime + ".txt");
		//set the output path and filename
		Path outputFilename = null;
		if (savingCiphertext) {
			outputFilename = Paths.get(OUTPUT_PATH + filename + "_was_encrypted" + dateAndTimeAndExtension);
		}
		else {
			outputFilename = Paths.get(OUTPUT_PATH + filename + "_was_decrypted" + dateAndTimeAndExtension);
		}
		if (debugging) {
			System.out.println("FILE WRITING - Filename: " + outputFilename);
			System.out.println("Output Text: " + inputEncodedString);
		}
		//write to file
		BufferedWriter stdoutFile = Files.newBufferedWriter(outputFilename);
		stdoutFile.write(inputEncodedString);
		//need to close and flush the buffer to ensure everything is written to the file
		stdoutFile.close();
		return outputFilename.toString();
	}
}
