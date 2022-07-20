package com.steitz.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.util.UUID;

import org.bouncycastle.util.Arrays;
import org.junit.Test;

public class JdkPGPTest {
        @Test
        public void testGeneratedKeys()
                        throws Exception {
                final String clearText = "hellogoodbye";
                ByteArrayInputStream bais = new ByteArrayInputStream(clearText
                                .getBytes());
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final KeyPair keyPair = KeyUtils.generateKeyPair();
                JdkPGP.encrypt(bais, baos, keyPair.getPublic());
                final byte[] cipherText = baos.toByteArray();
                System.out.println("Got " + cipherText.length + " ciphertext bytes");
                final ByteArrayInputStream cbais = new ByteArrayInputStream(cipherText);
                final ByteArrayOutputStream cbaos = new ByteArrayOutputStream();
                JdkPGP.decrypt(keyPair.getPrivate(), cbais, cbaos);
                final String decryptedString = cbaos.toString();
                assertEquals(clearText, decryptedString);
        }

        @Test
        public void testEncryptDecryptFiles()
                        throws Exception {
                final String clearTextFilePath = Thread.currentThread()
                                .getContextClassLoader().getResource("com/steitz/crypto/clear.txt")
                                .getFile();
                final String cipherTextFilePath = clearTextFilePath
                                .substring(0, clearTextFilePath.lastIndexOf('.')) + ".gpg";
                final KeyPair keyPair = KeyUtils.generateKeyPair();

                JdkPGP.encryptFile(cipherTextFilePath, clearTextFilePath,
                                keyPair.getPublic());
                JdkPGP.decryptFile(cipherTextFilePath,
                                clearTextFilePath + ".decrypted",
                                keyPair.getPrivate());
                assertEquals(BCPGPTest.fileToString(clearTextFilePath),
                                BCPGPTest.fileToString(clearTextFilePath + ".decrypted"));
        }

        @Test
        public void testEncryptDecryptString() throws Exception {
                String testString = UUID.randomUUID().toString();

                for (int i = 0; i < 100; i++) {
                        testString = testString + UUID.randomUUID().toString();
                }

                final KeyPair keyPair = KeyUtils.generateKeyPair();
                final byte[] cipherText = JdkPGP.encrypt(testString, keyPair.getPublic());
                assertEquals(testString,
                                JdkPGP.decrypt(cipherText, keyPair.getPrivate()));
        }

        @Test
        public void testEncryptDecryptLongStream() throws Exception {
                final byte[] clearText = KeyUtils.randomBytes(10000);
                final ByteArrayInputStream bais = new ByteArrayInputStream(clearText);
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final KeyPair keyPair = KeyUtils.generateKeyPair();
                JdkPGP.encrypt(bais, baos, keyPair.getPublic());
                final byte[] encryptedBytes = baos.toByteArray();
                final ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
                JdkPGP.decrypt(keyPair.getPrivate(), new ByteArrayInputStream(encryptedBytes), decryptedStream);
                final byte[] decryptedBytes = decryptedStream.toByteArray();
                assertTrue(Arrays.areEqual(clearText, decryptedBytes));
        }

}
