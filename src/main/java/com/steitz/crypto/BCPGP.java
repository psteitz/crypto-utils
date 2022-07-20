package com.steitz.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

/**
 * PGP encryption and decryption utilities using the BouncyCastle provider.
 */
public final class BCPGP {

        /** Default algorithm for generated keys */
        private static final BigInteger DEFAULT_EXPONENT = new BigInteger("10001", 16);

        /** Default length for generated keys */
        private static final int DEFAULT_KEY_LENGTH = 2048;

        /** Default certainty for generated keys */
        private static final int DEFAULT_CERTAINTY = 80;

        /** Default input buffer size */
        private static final int DEFAULT_BUFFER_SIZE = 256;

        /** Hide constructor */
        private BCPGP() {
        }

        /**
         * Decrypts a file and writes decrypted data to another file.
         *
         * @param cipherTextFilePath full path to the encrypted file
         * @param decryptedFilePath  full path to the cleartext output file
         * @param privateKey         PGP private key to use in decryption
         * @param passPhrase         passphrase for the private key
         * @throws InvalidCipherTextException
         * @throws IOException
         * @throws PGPException
         */
        public static void decryptFile(final String cipherTextFilePath,
                        final String decryptedFilePath,
                        final PGPSecretKey privateKey,
                        final String passPhrase)
                        throws InvalidCipherTextException,
                        IOException,
                        PGPException {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                decryptFileToStream(cipherTextFilePath, privateKey,
                                passPhrase, baos);
                baos.writeTo(new FileOutputStream(decryptedFilePath));
                baos.close();
        }

        /**
         * Decrypts a file and returns a byte array containing the decrypted data
         * from the file.
         *
         * @param cipherTextFilePath full path to the encrypted file
         * @param privateKey         PGP private key to use in decryption
         * @param passPhrase         passphrase for the private key
         * @return decrypted bytes
         * @throws InvalidCipherTextException
         * @throws IOException
         * @throws PGPException
         */
        public static byte[] decryptFileToByteArray(final String cipherTextFilePath,
                        final PGPSecretKey privateKey,
                        final String passPhrase)
                        throws InvalidCipherTextException,
                        IOException,
                        PGPException {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                decryptFileToStream(cipherTextFilePath, privateKey,
                                passPhrase, baos);
                return baos.toByteArray();
        }

        /**
         * Decrpts an input stream presumed to contain ciphertext bytes encrypted
         * for the given private key and writes the decrypted clear text bytes to the
         * output stream.
         *
         * @param privateKey   PGP private key to use in decryption
         * @param inputStream  input stream contaiing the ciphertext bytes
         * @param outputStream output stream to write cleartext bytes to
         * @throws IOException  if an IO error occurs
         * @throws PGPException if a decryption error occurs
         */
        public static void decrypt(final PGPPrivateKey privateKey,
                        final InputStream inputStream,
                        final OutputStream outputStream)
                        throws IOException,
                        PGPException {

                // Wrap the input stream in a decoder stream to extract PGPObjects
                final InputStream decoderInputStream = PGPUtil
                                .getDecoderStream(inputStream);

                // Attach a PGP object factory to the stream
                final PGPObjectFactory pgpFactory = new PGPObjectFactory(decoderInputStream,
                                new BcKeyFingerprintCalculator());

                // Get the first object in the stream. If it is not a PGPEncryptedDataList,
                // skip past it and assume the next item is the list of encrypted data objects.
                final Object pgpObject = pgpFactory.nextObject();
                PGPEncryptedDataList encryptedDataList;
                if (pgpObject instanceof PGPEncryptedDataList) {
                        encryptedDataList = (PGPEncryptedDataList) pgpObject;
                } else {
                        encryptedDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
                }

                // Iterate through the enctypted data list, saving the last one in
                // encryptedPayLoad.
                final Iterator<PGPEncryptedData> encryptedDataIterator = encryptedDataList
                                .getEncryptedDataObjects();
                PGPPublicKeyEncryptedData encryptedPayload = null;
                while (encryptedDataIterator.hasNext()) {
                        encryptedPayload = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();
                }

                // Set up decryption pipeline
                InputStream clearStream = encryptedPayload
                                .getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
                final JcaPGPObjectFactory compressedObjectFactory = new JcaPGPObjectFactory(clearStream);
                PGPCompressedData compressedData = (PGPCompressedData) compressedObjectFactory.nextObject();
                final JcaPGPObjectFactory literalDataFactory = new JcaPGPObjectFactory(compressedData.getDataStream());
                PGPLiteralData literalData = (PGPLiteralData) literalDataFactory.nextObject();
                InputStream literalDataStream = literalData.getDataStream();

                // Stream out decrypted bytes
                int ch;
                while ((ch = literalDataStream.read()) >= 0) {
                        outputStream.write(ch);
                }
                decoderInputStream.close();
                inputStream.close();
        }

        /**
         * Extract private key from secret key and passphrase.
         *
         * @param secretKey  PGPSectretKey
         * @param passPhrase passphrase
         * @return private key
         * @throws PGPException if an error occurs extracting the key
         */
        public static PGPPrivateKey extractPrivateKey(final PGPSecretKey secretKey, final String passPhrase)
                        throws PGPException {
                return secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(
                                new BcPGPDigestCalculatorProvider())
                                .build(passPhrase.toCharArray()));
        }

        /**
         * Decrpts an input stream presumed to contain ciphertext bytes encrypted
         * for the given private key and writes the decrypted clear text bytes to the
         * output stream.
         *
         * @param secretKey    PGPSecretKey to use in decryption
         * @param passPhrase   passphrase for secretKey
         * @param inputStream  input stream contaiing the ciphertext bytes
         * @param outputStream output stream to write cleartext bytes to
         * @throws IOException  if an IO error occurs
         * @throws PGPException if a decryption error occurs
         */
        public static void decrypt(final PGPSecretKey secretKey,
                        final String passPhrase, final InputStream inputStream,
                        final OutputStream outputStream)
                        throws IOException,
                        PGPException {

                decrypt(extractPrivateKey(secretKey, passPhrase), inputStream, outputStream);
        }

        /**
         * Decrypts a file to an output stream.
         *
         * @param cipherTextFilePath full path to the encrypted file
         * @param privateKey         PGP private key to use in decryption
         * @param passPhrase         passphrase for the private key
         * @param outputStream       output stream to receive the decrypted data
         * @throws IOException                if an IO error occurs
         * @throws PGPException               if an decryption error occurs
         * @throws InvalidCipherTextException if the ciphertext is invalid
         */
        public static void decryptFileToStream(final String cipherTextFilePath,
                        final PGPSecretKey privateKey,
                        final String passPhrase,
                        final OutputStream outputStream)
                        throws IOException,
                        PGPException,
                        InvalidCipherTextException {

                final InputStream fileStream = new FileInputStream(cipherTextFilePath);
                decrypt(privateKey, passPhrase, fileStream, outputStream);
        }

        /**
         * Decrypts a file to an output stream.
         *
         * @param cipherTextFilePath full path to the encrypted file
         * @param privateKey         PGP private key to use in decryption
         * @param outputStream       output stream to receive the decrypted data
         * @throws IOException                if an IO error occurs
         * @throws PGPException               if an decryption error occurs
         * @throws InvalidCipherTextException if the ciphertext is invalid
         */
        public static void decryptFileToStream(final String cipherTextFilePath,
                        final PGPPrivateKey privateKey,
                        final OutputStream outputStream)
                        throws IOException,
                        PGPException,
                        InvalidCipherTextException {

                final InputStream fileStream = new FileInputStream(cipherTextFilePath);
                decrypt(privateKey, fileStream, outputStream);
        }

        /**
         * PGP encrypt an input stream to an output stream using the provided public
         * key.
         * <p>
         * The entire input stream is read into memory and the output ciphertext is
         * written to an internal byte array. Therefore, this method is not suitable
         * for very large streams. Both inputStream and outputStream are closed by
         * this method.
         *
         * @param inputStream  stream of input bytes
         * @param outputStream output stream of encrypted bytes
         * @param publicKey    public key to encrypt the stream for
         * @throws IOException  if an IO error occurs
         * @throws PGPException if an encryption error occurs
         */
        public static void encrypt(final InputStream inputStream,
                        final OutputStream outputStream,
                        final PGPPublicKey publicKey)
                        throws IOException,
                        PGPException {

                // Input buffer
                final byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
                // Output buffer
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();

                // Compressed data generator
                final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
                                PGPCompressedData.ZIP);

                // Stream the full input stream to the compressed data generator
                writeStreamToLiteralData(compressedDataGenerator.open(baos), PGPLiteralData.BINARY,
                                inputStream, buffer);
                compressedDataGenerator.close();

                // Get an encrypted data generator that will generate an AES session key and use
                // it to encrypt the compressed data. Also encrypts the AES key with publicKey
                // and includes that in the output stream.
                final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                                                .setSecureRandom(new SecureRandom()));
                encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
                final byte[] bytes = baos.toByteArray();

                // Connect the encrypted data generator to the output stream
                final OutputStream encryptedDataStream = encryptedDataGenerator.open(outputStream, bytes.length);

                // Write the compressed, encrypted data to the output stream
                encryptedDataStream.write(bytes);

                // Close streams
                encryptedDataStream.close();
                outputStream.close();
                inputStream.close();
        }

        /**
         * PGP encrypts a string and returns an array of bytes containing the
         * cipertext.
         *
         * @param inputString string to encrypt
         * @param publicKey   public key to encrypt the string for
         * @return array of encrypted bytes
         * @throws IOException  if an IO error occurs
         * @throws PGPException if an encryption error occurs
         */
        public static byte[] encrypt(final String inputString, final PGPPublicKey publicKey)
                        throws IOException,
                        PGPException {
                final ByteArrayInputStream bais = new ByteArrayInputStream(Base64.encode(inputString.getBytes()));
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                encrypt(bais, baos, publicKey);
                return baos.toByteArray();
        }

        /**
         * Decrypt a byte array to a String. Assumes the original cleartext was Base64
         * encoded.
         *
         * @param cipherText encrypted bytes
         * @param secretKey  PGPSecretKey for decryption
         * @param passPhrase passphrase for the secret key
         * @return clear text as a String (after Base64 decoding)
         * @throws IOException
         * @throws PGPException
         */
        public static String decrypt(final byte[] cipherText, final PGPSecretKey secretKey,
                        final String passPhrase)
                        throws IOException,
                        PGPException {
                return decrypt(cipherText, extractPrivateKey(secretKey, passPhrase));
        }

        /**
         * Decrypt a byte array to a String. Assumes the original cleartext was Base64
         * encoded.
         *
         * @param cipherText encrypted bytes
         * @param privateKey private key
         * @return clear text as a String (after Base64 decoding)
         * @throws IOException
         * @throws PGPException
         */
        public static String decrypt(final byte[] cipherText, final PGPPrivateKey privateKey)
                        throws IOException,
                        PGPException {
                final ByteArrayInputStream bais = new ByteArrayInputStream(cipherText);
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                decrypt(privateKey, bais, baos);
                return new String(Base64.decode(baos.toByteArray()));
        }

        /**
         * Encrypt a file for a given public key.
         *
         * @param cipherTextFilePath full path for the output (encrypted) file
         * @param clearTextFilePath  fulll path of the input file
         * @param publicKey          public key to encrypt the file for
         * @throws IOException
         * @throws NoSuchProviderException
         * @throws PGPException
         */
        public static void encryptFile(final String cipherTextFilePath,
                        final String clearTextFilePath,
                        final PGPPublicKey publicKey)
                        throws IOException,
                        NoSuchProviderException,
                        PGPException {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
                                PGPCompressedData.ZIP);
                PGPUtil.writeFileToLiteralData(compressedDataGenerator.open(baos),
                                PGPLiteralData.BINARY,
                                new File(clearTextFilePath));
                compressedDataGenerator.close();
                PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES)
                                                .setSecureRandom(new SecureRandom()));
                encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
                byte[] bytes = baos.toByteArray();
                final OutputStream out = new FileOutputStream(cipherTextFilePath);
                OutputStream cOut = encryptedDataGenerator.open(out, bytes.length);
                cOut.write(bytes);
                cOut.close();
                out.close();
        }

        /**
         * Get PGPSecretKey from PGPKeyPair.
         *
         * @param keyPair PGPKeyPair instance
         * @return the PGPSecretKey from the key pari
         * @throws PGPException if the key is not valid
         */
        public static PGPSecretKey secretKeyFromKeyPair(final PGPKeyPair keyPair) throws PGPException {
                final PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build()
                                .get(HashAlgorithmTags.SHA256);
                return new PGPSecretKey(keyPair.getPrivateKey(), keyPair.getPublicKey(),
                                digestCalculator, false, null);

        }

        /**
         * Generate a new PGPKeyPair.
         *
         * @return newly generated key pair
         * @throws PGPException if an error occurs creating the key pair
         */
        public static PGPKeyPair generateKeyPair() throws PGPException {

                final RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
                keyPairGenerator.init(new RSAKeyGenerationParameters(DEFAULT_EXPONENT,
                                new SecureRandom(), DEFAULT_KEY_LENGTH, DEFAULT_CERTAINTY));

                AsymmetricCipherKeyPair cipherParms = keyPairGenerator.generateKeyPair();
                return new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, cipherParms, new Date());
        }

        /**
         * Write a stream of bytes to an output stream as literal data.
         *
         * @param outputStream output stream
         * @param fileType     format of the literal data that will be written to
         *                     the output stream (one of BINARY, TEXT or UTF8)
         * @param inputStream  input stream
         * @param buffer       buffer
         * @throws IOException
         */
        private static void writeStreamToLiteralData(final OutputStream outputStream, final char fileType,
                        final InputStream inputStream, final byte[] buffer)
                        throws IOException {
                final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
                final OutputStream literalDataStream = literalDataGenerator.open(outputStream, fileType, "", new Date(),
                                buffer);
                StreamUtils.pipeStreamContents(inputStream, literalDataStream, buffer.length);
        }

}
