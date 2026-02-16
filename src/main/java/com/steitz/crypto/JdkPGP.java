package com.steitz.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * PGP using JDK providers.
 */
public final class JdkPGP {

    /** Default transformation */
    private static final String DEFAULT_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private JdkPGP() {
    } // Hide constructor

    /**
     * RSA encrypt an input stream to an output stream using the provided public
     * key.
     *
     * @param inputStream  stream of input bytes
     * @param outputStream output stream of encrypted bytes
     * @param publicKey    public key to encrypt the stream for
     * @throws IOException         if an IO error occurs
     * @throws InvalidKeyException if the public key is not valid
     *
     */
    public static void encrypt(final InputStream inputStream,
            final OutputStream outputStream,
            final PublicKey publicKey)
            throws IOException,
            InvalidKeyException {

        try {
            // Get the length of the public key and set encryption block size accordingly.
            // OAEP with SHA-256 has 66 bytes overhead (2 * 32 + 2)
            final int keyLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
            final int blockSize = keyLength / 8 - 66; // 2048 -> 190, 3072 -> 318

            // Create and initialize an RSA encryption Cipher
            final Cipher encryptionCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Pipe the input stream through the cipher to the output stream
            StreamUtils.pipeTransformedStream(inputStream, outputStream, blockSize,
                    bytes -> {
                        try {
                            return encryptionCipher.doFinal(bytes);
                        } catch (IllegalBlockSizeException | BadPaddingException e) {
                            throw new IllegalStateException("Encryption failed", e);
                        }
                    });
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new IllegalStateException("RSA encryption not available.", ex);
        } finally {
            inputStream.close();
            outputStream.close();
        }
    }

    /**
     * Decrypts an input stream presumed to contain ciphertext bytes encrypted
     * for the given public key and writes the decrypted clear text bytes to the
     * output stream.
     *
     * @param privateKey   private key to use in decryption
     * @param inputStream  input stream containing the ciphertext bytes
     * @param outputStream output stream to write cleartext bytes to
     * @throws IOException         if an IO error occurs
     * @throws InvalidKeyException if the private key is not valid
     */
    public static void decrypt(final PrivateKey privateKey,
            final InputStream inputStream,
            final OutputStream outputStream)
            throws IOException, InvalidKeyException {

        try {
            // Get the length of the private key and set decryption block size accordingly.
            final int keyLength = ((RSAPrivateKey) privateKey).getModulus().bitLength();
            final int blockSize = keyLength / 8; // 2048 -> 256, 3072 -> 384
            final Cipher decryptionCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
            decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
            StreamUtils.pipeTransformedStream(inputStream, outputStream, blockSize,
                    bytes -> {
                        try {
                            return decryptionCipher.doFinal(bytes);
                        } catch (IllegalBlockSizeException | BadPaddingException e) {
                            throw new IllegalStateException("Decryption failed", e);
                        }
                    });
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new IllegalStateException("RSA encryption not available.", ex);
        } finally {
            outputStream.close();
            inputStream.close();
        }
    }

    /**
     * Encrypt a file for a given public key.
     *
     * @param cipherTextFilePath full path for the output (encrypted) file
     * @param clearTextFilePath  fulll path of the input file
     * @param publicKey          public key to encrypt the file for
     * @throws IOException
     * @throws InvalidKeyException
     */
    public static void encryptFile(final String cipherTextFilePath,
            final String clearTextFilePath,
            final PublicKey publicKey)
            throws IOException, InvalidKeyException {
        FileInputStream inputStream = new FileInputStream(clearTextFilePath);
        FileOutputStream outputStream = new FileOutputStream(cipherTextFilePath);
        encrypt(inputStream, outputStream, publicKey);
    }

    /**
     * Decrypts a file and writes decrypted data to another file.
     *
     * @param cipherTextFilePath full path to the encrypted file
     * @param clearTextFilePath  full path to the cleartext output file
     * @param privateKey         PGP private key to use in decryption
     * @throws IOException
     * @throws InvalidKeyException
     */
    public static void decryptFile(final String cipherTextFilePath,
            final String clearTextFilePath,
            final PrivateKey privateKey)
            throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException {
        FileInputStream inputStream = new FileInputStream(cipherTextFilePath);
        FileOutputStream outputStream = new FileOutputStream(clearTextFilePath);
        decrypt(privateKey, inputStream, outputStream);
    }

    /**
     * PGP encrypts a string and returns an array of bytes containing the
     * cipertext. Base64 encodes the input string before encryption.
     *
     * @param inputString string to encrypt
     * @param publicKey   public key to encrypt the string for
     * @return array of encrypted bytes
     * @throws IOException         if an IO error occurs
     * @throws InvalidKeyException
     */
    public static byte[] encrypt(final String inputString, final PublicKey publicKey)
            throws IOException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        final ByteArrayInputStream bais = new ByteArrayInputStream(inputString.getBytes());
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypt(bais, baos, publicKey);
        return baos.toByteArray();
    }

    /**
     * Decrypt a byte array to a String. Assumes the original cleartext was Base64
     * encoded.
     *
     * @param cipherText encrypted bytes
     * @param privateKey private key
     * @return clear text as a String (after Base64 decoding)
     * @throws IOException
     * @throws InvalidKeyException
     */
    public static String decrypt(final byte[] cipherText, final PrivateKey privateKey)
            throws IOException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        final ByteArrayInputStream bais = new ByteArrayInputStream(cipherText);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        decrypt(privateKey, bais, baos);
        return new String(baos.toByteArray());
    }
}
