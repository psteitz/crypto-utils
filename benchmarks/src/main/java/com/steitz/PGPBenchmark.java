package com.steitz;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Setup;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

import com.steitz.crypto.BCPGP;
import com.steitz.crypto.BCPGPTest;
import com.steitz.crypto.AES;
import com.steitz.crypto.JdkPGP;
import com.steitz.crypto.KeyUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

public class PGPBenchmark {

    /** Number of random test byte arrays strings to generate */
    private final static int NUM_TEST_STRINGS = 50;

    /** Length of test byte arrays */
    private static final int TEST_ARRAY_LENTH = 64;

    /** Source of random data */
    private static final Random RANDOM = new Random();

    /** Test strings */
    private static final ArrayList<String> TEST_STRINGS = new ArrayList<>();

    /** Test string length switch */
    private enum TestStringLength {
        SHORT, MEDIUM, LONG
    }

    @State(Scope.Thread)
    public static class MyState {
        public long successes = 0;
        public long failures = 0;
        public byte[] bcCipherText;
        public byte[] jdkCipherText;
        public PGPPublicKey harrysPublicKey;
        public PGPSecretKey harrysSecretKey;
        public PGPPrivateKey harrysPrivateKey;
        public String harrysPassphrase;
        public KeyPair testPair;
        public String shortTestString = "";
        public String mediumTestString = "";
        public String longTestString = "";
        public String clearText = "";
        /**
         * test string length - SHORT is one 64-byte block, MEDIUM is 25 x 64,
         * LONG is 50 x 64
         */
        public final TestStringLength testStringLength = TestStringLength.LONG;

        @TearDown(Level.Trial)
        public void doTearDown() {
            System.out.println("successes: " + successes);
            System.out.println("failures: " + failures);
        }

        @Setup(Level.Trial)
        public void deSetup() {
            try {

                // Generate test string data
                for (int i = 0; i < NUM_TEST_STRINGS; i++) {
                    final byte[] testBytes = new byte[TEST_ARRAY_LENTH];
                    RANDOM.nextBytes(testBytes);
                    TEST_STRINGS.add(Hex.encodeHexString(testBytes));
                }

                // Generate test strings
                shortTestString = TEST_STRINGS.get(0);
                final StringBuilder buffer = new StringBuilder();
                for (int i = 0; i < NUM_TEST_STRINGS; i++) {
                    buffer.append(TEST_STRINGS.get(i));
                    if (i == NUM_TEST_STRINGS / 2) {
                        mediumTestString = buffer.toString();
                    }
                }
                longTestString = buffer.toString();

                // Generate test keys
                harrysPublicKey = BCPGPTest.getHarrysPublicKey();
                harrysSecretKey = BCPGPTest.getHarrysSecretKey();
                harrysPassphrase = BCPGPTest.getHarrysPasshrase();
                harrysPrivateKey = BCPGP.extractPrivateKey(harrysSecretKey, harrysPassphrase);
                testPair = KeyUtils.generateKeyPair();

                // Set clearText and encrypt the test strings
                switch (testStringLength) {
                    case SHORT:
                        clearText = shortTestString;
                        break;
                    case MEDIUM:
                        clearText = mediumTestString;
                        break;
                    case LONG:
                        clearText = longTestString;
                }
                bcCipherText = BCPGP.encrypt(clearText, harrysPublicKey);
                jdkCipherText = JdkPGP.encrypt(clearText, testPair.getPublic());

            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    @Fork(value = 1, warmups = 2)
    @Benchmark
    @Threads(Threads.MAX)
    @BenchmarkMode(Mode.Throughput)
    public byte[] testPGPEncryptJDK(MyState state) {
        try {
            final byte[] cipherText = JdkPGP.encrypt(state.clearText, state.testPair.getPublic());
            state.successes++;
            return cipherText;
        } catch (Exception ex) {
            state.failures++;
            ex.printStackTrace();
        }
        return null;
    }

    @Fork(value = 1, warmups = 2)
    @Threads(Threads.MAX)
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String testPGPDecryptJDK(MyState state) throws Exception {
        try {
            final String out = JdkPGP.decrypt(state.jdkCipherText, state.testPair.getPrivate());
            state.successes++;
            return out;
        } catch (Exception ex) {
            state.failures++;
            ex.printStackTrace();
        }
        return null;
    }

    @Fork(value = 1, warmups = 2)
    @Benchmark
    @Threads(Threads.MAX)
    @BenchmarkMode(Mode.Throughput)
    public byte[] testPGPEncryptBC(MyState state) {
        try {
            final byte[] cipherText = BCPGP.encrypt(state.clearText, state.harrysPublicKey);
            state.successes++;
            return cipherText;
        } catch (Exception ex) {
            state.failures++;
            ex.printStackTrace();
        }
        return null;
    }

    @Fork(value = 1, warmups = 2)
    @Threads(Threads.MAX)
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String testDecryptBC(MyState state) throws Exception {
        try {
            final String out = BCPGP.decrypt(state.bcCipherText, state.harrysSecretKey, state.harrysPassphrase);
            state.successes++;
            return out;
        } catch (Exception ex) {
            state.failures++;
            ex.printStackTrace();
        }
        return null;
    }

    @Fork(value = 1, warmups = 2)
    @Threads(Threads.MAX)
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String testDecryptBCKeyProvided(MyState state) throws Exception {
        try {
            final String out = BCPGP.decrypt(state.bcCipherText, state.harrysPrivateKey);
            state.successes++;
            return out;
        } catch (Exception ex) {
            state.failures++;
            ex.printStackTrace();
        }
        return null;
    }
}
