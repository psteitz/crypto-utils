package com.steitz.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;
import org.junit.Test;

public class AESTest {

    @Test
    public void testFixedLengthEncryptDecryptKeyFromPassphrase()
            throws Exception {
        final String passphrase = "secret";
        final String clearText = "Hello, I love you won't you tell me your name.";
        final byte[] iv = KeyUtils.randomBytes(AES.IV_BYTES);
        final byte[] salt = KeyUtils.randomBytes(20);
        final SecretKey secretKey = KeyUtils.generateAESKeyFromPhrase(passphrase, salt);
        final byte[] cipherText = AES.encrypt(clearText.getBytes(), secretKey, iv);
        assertEquals(clearText, new String(AES.decrypt(cipherText, secretKey, iv)));
    }

    @Test
    public void testFixedLengthEncryptDecrypt()
            throws Exception {
        final String clearText = "Hello, I love you won't you tell me your name.";
        final SecretKey secretKey = KeyUtils.generateAESKey(AES.AES_KEY_LENGTH);
        final byte[] iv = KeyUtils.randomBytes(AES.IV_BYTES);
        final byte[] cipherText = AES.encrypt(clearText.getBytes(), secretKey, iv);
        assertEquals(clearText, new String(AES.decrypt(cipherText, secretKey, iv)));
    }

    @Test
    public void testSingleBlockStreamEncryptDecrypt()
            throws Exception {
        checkStream("Hello, I love you won't you tell me your name.");
    }

    @Test
    public void testLongStreamEncryptDecrypt() throws Exception {
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            buffer.append(UUID.randomUUID().toString());
        }
        checkStream(buffer.toString());

    }

    // Check stream encryption with iv passed explicitly
    private void checkStream(String clearText) throws Exception {
        final SecretKey secretKey = KeyUtils.generateAESKey(AES.AES_KEY_LENGTH);
        final byte[] iv = KeyUtils.randomBytes(AES.IV_BYTES);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AES.encrypt(new ByteArrayInputStream(clearText.getBytes(StandardCharsets.UTF_8)), baos, secretKey, iv);
        final byte[] cipherText = baos.toByteArray();
        final ByteArrayOutputStream clearOutputStream = new ByteArrayOutputStream();
        AES.decrypt(new ByteArrayInputStream(cipherText), clearOutputStream, secretKey, iv);
        assertEquals(clearText, new String(clearOutputStream.toByteArray()));
    }

    // Check stream encryption with IV auto-generated and prepended to streams
    private void checkStreamAutoIV(String clearText) throws Exception {
        final SecretKey secretKey = KeyUtils.generateAESKey(AES.AES_KEY_LENGTH);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AES.encrypt(new ByteArrayInputStream(clearText.getBytes(StandardCharsets.UTF_8)), baos, secretKey);
        final byte[] cipherText = baos.toByteArray();
        final ByteArrayOutputStream clearOutputStream = new ByteArrayOutputStream();
        AES.decrypt(new ByteArrayInputStream(cipherText), clearOutputStream, secretKey);
        assertEquals(clearText, new String(clearOutputStream.toByteArray()));
    }

    @Test
    public void testSingleBlockStreamEncryptDecryptAutoIV()
            throws Exception {
        checkStreamAutoIV("Hello, I love you won't you tell me your name.");
    }

    @Test
    public void testLongStreamEncryptDecryptAutoIV() throws Exception {
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            buffer.append(UUID.randomUUID().toString());
        }
        checkStreamAutoIV(buffer.toString());
    }

    @Test
    public void testFixedLengthWithIV() throws Exception {
        final String clearText = "You want everything on a silver platter.";
        final String passphrase = "password";
        final byte[] salt = KeyUtils.randomBytes(AES.SALT_BYTES);
        final SecretKey secretKey = KeyUtils.generateAESKeyFromPhrase(passphrase, salt);
        final byte[] encrypted = AES.encrypt(clearText.getBytes(), secretKey);
        assertEquals(clearText, new String(AES.decrypt(encrypted, secretKey)));
    }

    @Test
    public void testFixedLengthEncryptDecryptLongText()
            throws Exception {
        final byte[] clearText = KeyUtils.randomBytes(10000);
        final SecretKey secretKey = KeyUtils.generateAESKey(AES.AES_KEY_LENGTH);
        final byte[] iv = KeyUtils.randomBytes(AES.IV_BYTES);
        final byte[] cipherText = AES.encrypt(clearText, secretKey, iv);
        assertTrue(Arrays.areEqual(clearText, AES.decrypt(cipherText, secretKey, iv)));
    }
}
