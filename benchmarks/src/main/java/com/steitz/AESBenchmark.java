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

public class AESBenchmark {

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
        public final String key = "foofoofoofoofoofoofoofoofoofoooo";
        public byte[] bcAESCipherText;
        public byte[] jdkAESCipherText;
        public String shortTestString = "";
        public String mediumTestString = "";
        public String longTestString = "";
        public byte[] clearText;
        public byte[] salt = KeyUtils.randomBytes(AES.SALT_BYTES);
        public byte[] iv = KeyUtils.randomBytes(AES.IV_BYTES);
        public SecretKey secretKey = KeyUtils.generateAESKeyFromPhrase(key, salt);
        /**
         * test string length - SHORT is one 64-byte block, MEDIUM is 25 x 64,
         * LONG is 50 x 64
         */
        public final TestStringLength testStringLength = TestStringLength.SHORT;

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

                // Set clearText and encrypt the test strings
                switch (testStringLength) {
                    case SHORT:
                        clearText = shortTestString.getBytes(StandardCharsets.UTF_8);
                        break;
                    case MEDIUM:
                        clearText = mediumTestString.getBytes(StandardCharsets.UTF_8);
                        break;
                    case LONG:
                        clearText = longTestString.getBytes(StandardCharsets.UTF_8);
                }
                jdkAESCipherText = AES.encrypt(clearText, secretKey, iv);

            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    @Fork(value = 1, warmups = 2)
    @Benchmark
    @Threads(Threads.MAX)
    @BenchmarkMode(Mode.Throughput)
    public byte[] testAESEncryptJDK(MyState state) {
        try {
            final byte[] cipherText = AES.encrypt(state.clearText, state.secretKey, state.iv);
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
    public byte[] testDecryptJDK(MyState state) throws Exception {
        final byte[] out = AES.decrypt(state.jdkAESCipherText, state.secretKey, state.iv);
        return out;
    }

    @Fork(value = 1, warmups = 2)
    @Benchmark
    @Threads(Threads.MAX)
    @BenchmarkMode(Mode.Throughput)
    public byte[] testAESEncryptBC(MyState state) {
        AES.setProvider("BC");
        try {
            final byte[] cipherText = AES.encrypt(state.clearText, state.secretKey, state.iv);
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
    public byte[] testDecryptBC(MyState state) throws Exception {
        AES.setProvider("BC");
        final byte[] out = AES.decrypt(state.jdkAESCipherText, state.secretKey, state.iv);
        return out;
    }
}
