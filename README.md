# AES CBC Padding Encryption & Decryption

## Database UDF

Both `src/main/java/AES_CBC_Padding_Decrypt.java`, `src/main/java/AES_CBC_Padding_Encrypt.java`, and `src/main/java/AES_CBC_PKCS5Padding_Java16.java` were compiled into database user defined functions in Teradata (Java 1.6) and Greenplum (Java 1.8), so encryption and decryption could take place between the 2. This was for a real life project with sensitive data.

## CLI Addon

After implementing the database UDF I kept trying to improve what I had built so I added a CLI component, `src/main/java/CLI.java` uses `src/main/java/AES_CBC_Padding_Decrypt.java` and `src/main/java/AES_CBC_Padding_Encrypt.java` to do encryption from the command line on files and strings.

## No Padding & KAT

Created this so I could use the Known Answer Tests (KAT).

## AES_CBC_PKCS5Padding_v3.java

This is the most advanced implementation of AES that I have done yet. It is the most advanced because it can cover files as well as text files. But also because it does message authentication through the use of HMACs. I tried to make this as close as possible to meeting the [NSA Cryptography Suite B recommendations.](https://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography) The one thing that is left to do is to integrate digital signing into this.

Basically this program will does AES cipher block chaining encryption or decryption using 128 bit, 192 bit, or 256 bit mode. It also uses PKCS#5 padding to pad out the data bytes length if it is not a multiple of 32, which is quite common.
