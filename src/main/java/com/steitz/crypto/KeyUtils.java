package com.steitz.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public final class KeyUtils {

    /** Hash iterations in PBE key generation */
    private static final int HASH_ITERATION_COUNT = 65536;

    /** Default length of generated PGP keys */
    private static final int DEFAULT_PGP_KEY_LENGTH = 3072;

    /** Default PGP algorithm */
    private static final String DEFAULT_ALGORITHM = "RSA";

    /** Hide constructor */
    private KeyUtils() {
    }

    /**
     * Generate a (secure) random byte array of the given length.
     *
     * @param numBytes length of the generated array
     * @return array of numBytes random bytes
     */
    public static byte[] randomBytes(final int numBytes) {
        final byte[] bytes = new byte[numBytes];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Strong PRNG not available");
        }
        return bytes;
    }

    /**
     * Generate a random AES key with the default key length (256 bits).
     *
     * @return randomly generated 256-bit AES key
     */
    public static SecretKey generateAESKey() {
        return generateAESKey(AES.AES_KEY_LENGTH);
    }

    /**
     * Generate a random AES key of the given bit length
     *
     * @param keysize length of the key in bits
     * @return AES key
     */
    public static SecretKey generateAESKey(final int keysize) {
        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keysize, SecureRandom.getInstanceStrong());
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            throw new IllegalStateException("Strong PRNG or AES not available");
        }
    }

    /**
     * Generate an AES key from a passphrase.
     *
     * @param passphrase passphrase to use
     * @param salt       random bytes to use as salt
     * @param iterations number of iterations for AES
     * @param length     length of the AES key to generate
     * @return AES key of the given length based on the provided passphrase and salt
     */
    public static SecretKey generateAESKeyFromPhrase(final String passphrase, final byte[] salt, final int iterations,
            final int length) {
        try {
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final KeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations, length);
            final SecretKey secretKey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
            return secretKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
            throw new IllegalStateException("Strong AES not available");
        }
    }

    /**
     * Generate an AES SecretKey from a passphrase and salt.
     *
     * @param passphrase passphrase for the key
     * @param salt       passhphrase salt
     * @return AES SecretKey based on the passphrase and salt
     */
    public static SecretKey generateAESKeyFromPhrase(final String passphrase, final byte[] salt) {
        return generateAESKeyFromPhrase(passphrase, salt, HASH_ITERATION_COUNT, AES.AES_KEY_LENGTH);
    }

    /**
     * Generate a PGP key pair for the given algorithm with the given key length in
     * bits.
     *
     * @param algorithm PGP algoritm - currently only "RSA" is fully supported
     * @param length    length of the key in bits
     * @return newly generated KeyPair instance
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    public static KeyPair generateKeyPair(final String algorithm, final int length) throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(length);
        return keyPairGenerator.genKeyPair();
    }

    /**
     * Generate a PGP key pair for the given algorithm with the default key length
     * ({@link #DEFAULT_PGP_KEY_LENGTH})
     *
     * @param algorithm
     * @return newly generated KeyPair instance
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    public static KeyPair generateKeyPair(final String algorithm) throws NoSuchAlgorithmException {
        return generateKeyPair(algorithm, DEFAULT_PGP_KEY_LENGTH);
    }

    /**
     * Generate a PGP key pair of the given length using the default algorithm
     * (RSA).
     *
     * @param length key length in bits
     * @return newly generated KeyPair instance
     * @throws NoSuchAlgorithmException if the default algorithm is not supported
     */
    public static KeyPair generateKeyPair(final int length) throws NoSuchAlgorithmException {
        return generateKeyPair(DEFAULT_ALGORITHM, length);
    }

    /**
     * Generate a PGP key pair using the default algorithm and key length.
     * DEFAULT_KEY_LENGTH
     *
     * @return newley generated KeyPair instance
     * @throws NoSuchAlgorithmException if the default algorithm is not supported
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return generateKeyPair(DEFAULT_ALGORITHM, DEFAULT_PGP_KEY_LENGTH);
    }

    /**
     * Reads the secret keys contained in an input stream from an exported
     * keyring file and returns them in a list.
     *
     * @param in stream containing data exported from a keyring file
     * @return list of private keys extracted from the stream
     * @throws IOException
     * @throws PGPException
     */
    public static List<PGPSecretKey> readSecretKeys(final InputStream in)
            throws IOException,
            PGPException {
        final PGPSecretKeyRingCollection keys = new PGPSecretKeyRingCollection(PGPUtil
                .getDecoderStream(in), new BcKeyFingerprintCalculator());
        final ArrayList<PGPSecretKey> privateKeys = new ArrayList<>();
        keys.forEach(key -> privateKeys.add(key.getSecretKey()));
        return privateKeys;
    }

    /**
     * Reads the public keys contained in an input stream from an exported
     * keyring file and returns them in a list.
     *
     * @param in stream containing data exported from a keyring file
     * @return list of pubkic keys extracted from the stream
     * @throws IOException
     * @throws PGPException
     */
    public static List<PGPPublicKey> readPublicKeys(final InputStream in)
            throws IOException,
            PGPException {
        final PGPSecretKeyRingCollection keys = new PGPSecretKeyRingCollection(PGPUtil
                .getDecoderStream(in), new BcKeyFingerprintCalculator());
        final ArrayList<PGPPublicKey> publicKeys = new ArrayList<>();
        keys.forEach(key -> publicKeys.add(key.getPublicKey()));
        return publicKeys;
    }

}
