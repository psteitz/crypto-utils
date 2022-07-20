package com.steitz.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

public class BCPGPTest {

    @Test
    public void testReadSecretKeys()
            throws Exception {
        final InputStream inputStream = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("com/steitz/crypto/testkeys.asc");
        final List<PGPSecretKey> testKeys = KeyUtils
                .readSecretKeys(inputStream);
        boolean foundHarry = false;
        boolean foundMary = false;
        for (PGPSecretKey key : testKeys) {
            if (key.getUserIDs().next().contains("harry@hacker.com")) {
                foundHarry = true;
            }
            if (key.getUserIDs().next().contains("mary@hacker.com")) {
                foundMary = true;
            }
        }
        assertTrue(foundHarry);
        assertTrue(foundMary);
    }

    @Test
    public void testReadPublicKeys()
            throws Exception {
        final InputStream inputStream = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("com/steitz/crypto/testkeys.asc");
        final List<PGPPublicKey> testKeys = KeyUtils
                .readPublicKeys(inputStream);
        boolean foundHarry = false;
        boolean foundMary = false;
        for (PGPPublicKey key : testKeys) {
            if (key.getUserIDs().next().contains("harry@hacker.com")) {
                foundHarry = true;
            }
            if (key.getUserIDs().next().contains("mary@hacker.com")) {
                foundMary = true;
            }
        }
        ;
        assertTrue(foundMary);
        assertTrue(foundHarry);
    }

    public static PGPPublicKey getHarrysPublicKey()
            throws Exception {
        final List<PGPPublicKey> testPublicKeys = KeyUtils
                .readPublicKeys(Thread.currentThread().getContextClassLoader()
                        .getResourceAsStream("com/steitz/crypto/testkeys.asc"));
        PGPPublicKey harryPublicKey = null;
        for (PGPPublicKey key : testPublicKeys) {
            if (key.getUserIDs().next().contains("harry@hacker.com")) {
                harryPublicKey = key;
            }
        }
        return harryPublicKey;
    }

    public static PGPSecretKey getHarrysSecretKey()
            throws Exception {
        final List<PGPSecretKey> testPrivateKeys = KeyUtils
                .readSecretKeys(Thread.currentThread().getContextClassLoader()
                        .getResourceAsStream("com/steitz/crypto/testkeys.asc"));
        PGPSecretKey harryPrivateKey = null;
        for (PGPSecretKey key : testPrivateKeys) {
            if (key.getUserIDs().next().contains("harry@hacker.com")) {
                harryPrivateKey = key;
            }
        }
        return harryPrivateKey;
    }

    public static PGPPrivateKey getHarrysPrivateKey() throws Exception {
        return BCPGP.extractPrivateKey(getHarrysSecretKey(), getHarrysPasshrase());
    }

    public static String getHarrysPasshrase() {
        return "foo";
    }

    @Test
    public void testEncryptDecryptFiles()
            throws Exception {
        final String clearTextFilePath = Thread.currentThread()
                .getContextClassLoader().getResource("com/steitz/crypto/clear.txt")
                .getFile();
        final String cipherTextFilePath = clearTextFilePath
                .substring(0, clearTextFilePath.lastIndexOf('.')) + ".gpg";
        final PGPPublicKey harryPublicKey = getHarrysPublicKey();

        BCPGP.encryptFile(cipherTextFilePath, clearTextFilePath,
                harryPublicKey);
        final PGPSecretKey harryPrivateKey = getHarrysSecretKey();
        BCPGP.decryptFile(cipherTextFilePath,
                clearTextFilePath + ".decrypted",
                harryPrivateKey, getHarrysPasshrase());
        assertEquals(fileToString(clearTextFilePath),
                fileToString(clearTextFilePath + ".decrypted"));
        final byte[] clearArray = BCPGP
                .decryptFileToByteArray(cipherTextFilePath, harryPrivateKey, "foo");
        assertEquals(fileToString(clearTextFilePath),
                new String(clearArray, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptDecryptFilesToStreams() throws Exception {
        final String clearTextFilePath = Thread.currentThread()
                .getContextClassLoader().getResource("com/steitz/crypto/clear.txt")
                .getFile();
        final String cipherTextFilePath = clearTextFilePath
                .substring(0, clearTextFilePath.lastIndexOf('.')) + ".gpg";
        final PGPPublicKey harryPublicKey = getHarrysPublicKey();

        BCPGP.encryptFile(cipherTextFilePath, clearTextFilePath,
                harryPublicKey);
        final PGPSecretKey harryPrivateKey = getHarrysSecretKey();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BCPGP.decryptFileToStream(cipherTextFilePath,
                harryPrivateKey, getHarrysPasshrase(), baos);
        assertEquals(fileToString(clearTextFilePath), baos.toString());
    }

    @Test
    public void testEncryptDecryptStreams()
            throws Exception {
        final String clearText = "hellogoodbye";
        ByteArrayInputStream bais = new ByteArrayInputStream(clearText
                .getBytes());
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BCPGP.encrypt(bais, baos, getHarrysPublicKey());
        final byte[] cipherText = baos.toByteArray();
        final ByteArrayInputStream cbais = new ByteArrayInputStream(cipherText);
        final ByteArrayOutputStream cbaos = new ByteArrayOutputStream();
        BCPGP.decrypt(getHarrysSecretKey(), getHarrysPasshrase(), cbais, cbaos);
        final String decryptedString = cbaos.toString();
        assertEquals(clearText, decryptedString);
    }

    @Test
    public void testEncryptDecryptLargeStreams() throws Exception {
        // Size of large test stream in bytes
        final int INPUT_STREAM_SIZE = 100000;

        // Generate INPUT_STREAM_SIZE random bytes into buffer
        final Random random = new Random();
        final byte[] buffer = new byte[INPUT_STREAM_SIZE];
        random.nextBytes(buffer);

        // Compute the hash of the data in the buffer
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        final byte[] clearhash = messageDigest.digest(buffer);

        // Pipe buffer as bais in encrypt(bais, baos, getHarrysPublicKey());
        final ByteArrayInputStream bais = new ByteArrayInputStream(buffer);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BCPGP.encrypt(bais, baos, getHarrysPublicKey());

        // baos gets ciphertext in encrypt call above
        final byte[] cipherText = baos.toByteArray();
        final ByteArrayInputStream cbais = new ByteArrayInputStream(cipherText);
        final ByteArrayOutputStream cbaos = new ByteArrayOutputStream();
        BCPGP.decrypt(getHarrysSecretKey(), getHarrysPasshrase(), cbais, cbaos);
        messageDigest.reset();
        final byte[] decryptedBuffer = cbaos.toByteArray();
        final byte[] decryptedHash = messageDigest.digest(decryptedBuffer);
        assertTrue(Arrays.areEqual(clearhash, decryptedHash));
    }

    @Test
    public void testEncryptDecryptString() throws Exception {
        final String testString = UUID.randomUUID().toString();
        final byte[] cipherText = BCPGP.encrypt(testString, getHarrysPublicKey());
        assertEquals(testString,
                BCPGP.decrypt(cipherText, getHarrysSecretKey(), getHarrysPasshrase()));
    }

    @Test
    public void testGeneratedKeys()
            throws Exception {
        final String clearText = "hellogoodbye";
        ByteArrayInputStream bais = new ByteArrayInputStream(clearText
                .getBytes());
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PGPKeyPair keyPair = BCPGP.generateKeyPair();
        BCPGP.encrypt(bais, baos, keyPair.getPublicKey());
        final byte[] cipherText = baos.toByteArray();
        final ByteArrayInputStream cbais = new ByteArrayInputStream(cipherText);
        final ByteArrayOutputStream cbaos = new ByteArrayOutputStream();
        final PGPSecretKey secretKey = BCPGP.secretKeyFromKeyPair(keyPair);
        BCPGP.decrypt(secretKey, "", cbais, cbaos);
        final String decryptedString = cbaos.toString();
        assertEquals(clearText, decryptedString);
    }

    protected static String fileToString(String filePath) {
        StringBuilder buffer = new StringBuilder();
        try (Stream<String> stream = Files.lines(Paths.get(filePath),
                StandardCharsets.UTF_8)) {
            stream.forEach(s -> buffer.append(s).append("\n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return buffer.toString();
    }
}
