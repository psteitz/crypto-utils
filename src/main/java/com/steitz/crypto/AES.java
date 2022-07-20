package com.steitz.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES Crypto using JDK GCM provider.
 */
public final class AES {

    /** AES tranformation - GCM with no padding */
    protected static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";

    /** Sun provider (default) */
    protected static final String SUN_PROVIDER = "SunJCE";

    /** Bouncy Castle provider */
    protected static final String BC_PROVIDER = "BC";

    /** Tag bits */
    protected static final int AES_TAG_BITS = 128;

    /** IV length in bytes */
    public static final int IV_BYTES = 12;

    /** Salt bytes used in PBE */
    public static final int SALT_BYTES = 16;

    /** AES key length */
    protected static final int AES_KEY_LENGTH = 256;

    /** Size of input buffer */
    protected static final int INPUT_BUFFER_SIZE = 128;

    private AES() {
    } // Hide constructor

    /** Crypto provider - defaults to Sun (jdk default). */
    private static String provider = "SunJCE";

    /**
     * Set the crypto provider name. Use SUN_PROVIDER or BC_PROVIDER for platform
     * default (the default) or BouncyCastle, resp.
     *
     * @param providerName name of crypto provider
     */
    public static synchronized void setProvider(final String providerName) {
        provider = providerName;
    }

    /**
     * @return AES provider name
     */
    public static synchronized String getProvider() {
        return provider;
    }

    /**
     * Encrypt clearText using secretKey with initialization vector iv. The returned
     * byte array is Base64 encoded.
     *
     * @param clearText byte array to be encrypted
     * @param secretKey AES SecretKey
     * @param iv        initialization vector
     * @return Base64-encoded ciphertext
     * @throws InvalidKeyException if the SecretKey is not valid
     */
    public static byte[] encrypt(final byte[] clearText, final SecretKey secretKey, final byte[] iv)
            throws InvalidKeyException {
        try {
            final Cipher cipher = getCipher(secretKey, Cipher.ENCRYPT_MODE, iv, null);
            final byte[] encryptedText = cipher.doFinal(clearText);
            return Base64.getEncoder().encode(encryptedText);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            // None of these exceptions should ever happen
            // Must be an error in library code or jdk configuration
            ex.printStackTrace();
            throw new IllegalStateException("Strong encryption not available.");
        }
    }

    /**
     * Encrypt cleartext input stream using secretKey with invialization vector iv,
     * writing ciphertext output bytes to outputStream. The output stream is
     * returned as raw bytes (not Base64 encoded). The output stream is closed on
     * successful completion.
     *
     * @param inputStream  input stream of bytes to encrypt
     * @param outputStream oubput stream to receive encrypted bytes
     * @param secretKey    SecretKey to use in encryption
     * @param iv           initialization vector
     * @throws InvalidKeyException if the key is not valid
     * @throws IOException         if an IO error occurs
     */
    public static void encrypt(final InputStream inputStream, final OutputStream outputStream,
            final SecretKey secretKey, final byte[] iv) throws InvalidKeyException, IOException {
        try {
            final Cipher cipher = getCipher(secretKey, Cipher.ENCRYPT_MODE, iv, null);
            StreamUtils.pipeTransformedStream(inputStream, outputStream, INPUT_BUFFER_SIZE,
                    bytes -> cipher.update(bytes));
            final byte[] endBytes = cipher.doFinal();
            outputStream.write(endBytes);
            outputStream.close();
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            // None of these exceptions should ever happen
            // Must be an error in library code or jdk configuration
            ex.printStackTrace();
            throw new IllegalStateException("Configuration error.");
        }
    }

    /**
     * Decrypt inputStream to outputStream using secretKey and iv.
     * <p>
     * Note: The iv is the initialization vector used when generating the ciphertext
     * in the inputStream. This may be provided at the beginning of the stream. In
     * that case, use {@link #decrypt(InputStream, OutputStream, SecretKey)}.
     *
     * @param inputStream  input stream of ciphertext bytes
     * @param outputStream output stream of cleartext bytes
     * @param secretKey    SecretKey used for decryption
     * @param iv           initialization vector used when ciphertext bytes were
     *                     created
     * @throws InvalidKeyException
     * @throws IOException
     */
    public static void decrypt(final InputStream inputStream, final OutputStream outputStream,
            final SecretKey secretKey,
            final byte[] iv) throws InvalidKeyException, IOException {
        try {
            final Cipher cipher = getCipher(secretKey, Cipher.DECRYPT_MODE, iv, null);
            StreamUtils.pipeTransformedStream(inputStream, outputStream, INPUT_BUFFER_SIZE,
                    bytes -> cipher.update(bytes));
            outputStream.write(cipher.doFinal());
            outputStream.close();
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            // None of these exceptions should ever happen
            // Must be an error in library code or jdk configuration
            ex.printStackTrace();
            throw new IllegalStateException("Strong encryption not available.");
        }
    }

    /**
     * Decrypt inputStream to outputStream using secretKey.
     * <p>
     * Notes:
     * <ol>
     * <li>This method assumes that the first IV_BYTES bytes in the inputStream
     * are the iv used when initializing the encryption cipher. This will be the
     * case if
     * {@link #encrypt(InputStream, OutputStream, SecretKey)} was used to generate
     * the input ciphertext stream. Use
     * {@link #decrypt(InputStream, OutputStream, SecretKey, byte[])} if the iv
     * needs to be supplied out of band.
     * </li>
     * <li>Both the input and output streams are raw bytes. The input stream
     * is not expected to be Base64 encoded and the output stream is not encoded.
     * </li>
     * </ol>
     *
     * @param inputStream  input stream of ciphertext bytes
     * @param outputStream output stream of cleartext bytes
     * @param secretKey    SecretKey used for decryption
     * @throws InvalidKeyException
     * @throws IOException
     */
    public static void decrypt(final InputStream inputStream, final OutputStream outputStream,
            final SecretKey secretKey) throws InvalidKeyException, IOException {
        // Get the iv from the beginning of the stream
        final byte[] iv = new byte[IV_BYTES];
        inputStream.read(iv);
        // Decrypt the rest of the input stream with ciper initialized using iv
        decrypt(inputStream, outputStream, secretKey, iv);
    }

    /**
     * Encrypt inputStream to outputStream using secretKey. A random iv is generated
     * to initialize the encryption cipher. The iv is written (unencrypted) to the
     * beginning of the output stream.
     *
     * @param inputStream  input stream of raw cleartext bytes (not Base64 encoded)
     * @param outputStream output stream of ciphertext bytes (not Base64 encoded)
     * @param secretKey    SecretKey used to encrypt
     * @throws InvalidKeyException if secretKey is not valid
     * @throws IOException         if an I/O error occurs
     */
    public static void encrypt(final InputStream inputStream, final OutputStream outputStream,
            final SecretKey secretKey) throws InvalidKeyException, IOException {
        // Generate iv and write it to the output stream
        final byte[] iv = KeyUtils.randomBytes(IV_BYTES);
        outputStream.write(iv);
        // Encrypt the input stream to the output with cipher initialized using iv
        encrypt(inputStream, outputStream, secretKey, iv);
    }

    /**
     * Encrypt clearText with secretKey. A random iv is generated and prepended to
     * the returned ciphertext. The returned byte array (with iv at the beginning)
     * is Base64 encoded.
     *
     * @param clearText byte array to be encrypted
     * @param secretKey AES SecretKey
     * @return Base-64 encoded iv + ciphertext
     * @throws InvalidKeyException if secretKey is not valid
     */
    public static byte[] encrypt(final byte[] clearText, final SecretKey secretKey) throws InvalidKeyException {
        return encryptWithIV(clearText, secretKey, KeyUtils.randomBytes(IV_BYTES));
    }

    /**
     * Decrypts cipherText using secretKey with cipher initialized by iv. The input
     * byte array is expected to be Base64 encoded.
     *
     * @param cipherText Base64 encoded ciphertext bytes
     * @param secretKey  AES SecretKey
     * @param iv         initialization vector
     * @return cleartext bytes
     * @throws InvalidKeyException if secretKey is not valid
     */
    public static byte[] decrypt(final byte[] cipherText, final SecretKey secretKey, final byte[] iv)
            throws InvalidKeyException {
        try {
            final Cipher cipher = getCipher(secretKey, Cipher.DECRYPT_MODE, iv, null);
            byte[] clearText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return clearText;
        } catch (IllegalBlockSizeException
                | BadPaddingException ex) {
            // None of these exceptions should ever happen
            // Must be error in library code or jdk
            ex.printStackTrace();
            throw new IllegalStateException("Strong encryption not available.");
        }
    }

    /**
     * Encrypt clearText with secretKey, using iv to initialize the cipher and
     * adding the iv bytes to the beginning of the ciphertext output. The ciphertext
     * output is Base64 encoded.
     *
     * @param clearText array of bytes to encrypt
     * @param secretKey AES SecretKey used in encryption
     * @param iv        initialization vector
     * @return Base64 encoded ciphertext bytes
     * @throws InvalidKeyException
     */
    public static byte[] encryptWithIV(final byte[] clearText, final SecretKey secretKey, final byte[] iv)
            throws InvalidKeyException {
        final byte[] cipherText = encrypt(clearText, secretKey, iv);
        final ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherText.length);
        buffer.put(iv).put(cipherText);
        return Base64.getEncoder().encode(buffer.array());
    }

    /**
     * Decrypt byte array containing iv followed by ciphertext. The full byte array
     * is expected to be Base64 encoded.
     *
     * @param ivPlusCipherText {@link #IV_BYTES} iv bytes followed by ciphertext
     * @param secretKey        AES SecretKey used for decryption
     *
     * @return clearText bytes
     * @throws InvalidKeyException if secretKey is invalid
     */
    public static byte[] decrypt(final byte[] ivPlusCipherText, final SecretKey secretKey) throws InvalidKeyException {
        final ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(ivPlusCipherText));
        final byte[] iv = new byte[IV_BYTES];
        buffer.get(iv);
        byte[] cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);
        return decrypt(cipherText, secretKey, iv);
    }

    /**
     * Get an AES cipher initialized using the provided key, mode and iv.
     * If providerName is "BC" and the BC provider is not loaded, an attempt will be
     * made to add the BouncyCastle provider.
     *
     * @param key          AES SecretKey
     * @param mode         one of Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param iv           initialzation vector
     * @param providerName crypto provider name - use null for JDK default
     * @return Cipher that has been initialized for mode with secretKey and iv
     * @throws InvalidKeyException if key is not valid
     */
    public static Cipher getCipher(final SecretKey key, final int mode, final byte[] iv, final String providerName)
            throws InvalidKeyException {

        if (provider == "BC" && Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        Cipher cipher = null;
        try {
            if (providerName == null) {
                cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
            } else {
                cipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            }
            cipher.init(mode, key, new GCMParameterSpec(AES_TAG_BITS, iv));
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException ex) {
            ex.printStackTrace();
            throw new IllegalStateException("Provider not available or correctly configured");
        }
        return cipher;
    }

}
