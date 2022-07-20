package com.steitz.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Base64;

public final class StreamUtils {

    private StreamUtils() {
    } // Hide constructor

    /**
     * Read the input stream and do buffered write of the bytes it contains to the
     * output stream. Closes both streams.
     *
     * @param inputStream  input stream
     * @param outputStream output stream
     * @param bufferSize   input buffer size
     * @throws IOException
     */
    public static void pipeStreamContents(final InputStream inputStream,
            final OutputStream outputStream, final int bufferSize)
            throws IOException {
        final byte[] buffer = new byte[bufferSize];

        try {
            int len;
            while ((len = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            outputStream.close();
        } finally {
            // Zero the buffer
            Arrays.fill(buffer, (byte) 0);
            try {
                inputStream.close();
            } catch (IOException ex) {
                // ignore, but dump stacktrace to syserr
                ex.printStackTrace();
            }
        }
    }

    /**
     * Read the input stream, do base64 decoding and write decoded bytes to the
     * output stream. Closes both streams.
     *
     * @param inputStream  input stream
     * @param outputStream output stream
     * @param bufferSize   input buffer size
     * @throws IOException
     */
    public static void pipeDecodedStreamContents(final InputStream inputStream,
            final OutputStream outputStream, final int bufferSize)
            throws IOException {
        final byte[] buffer = new byte[bufferSize];

        try {
            int len;
            while ((len = inputStream.read(buffer)) > 0) {
                final byte[] receivedBytes = Arrays.copyOf(buffer, len);
                final byte[] decodedBytes = Base64.getDecoder().decode(receivedBytes);
                outputStream.write(decodedBytes);
            }
            outputStream.close();
        } finally {
            // Zero the buffer
            Arrays.fill(buffer, (byte) 0);
            try {
                inputStream.close();
            } catch (IOException ex) {
                // ignore, but dump stacktrace to syserr
                ex.printStackTrace();
            }
        }
    }

    /**
     * Pipe the input stream to the output stream, running the transformer on each
     * block of input bytes.
     *
     * @param inputStream  input stream - closed at the end
     * @param outputStream output stream - left open at the end
     * @param bufferSize   transformer block size
     * @param transformer  byte[] -> byte[] transformer (usually a lambda)
     * @throws IOException
     */
    public static void pipeTransformedStream(final InputStream inputStream, final OutputStream outputStream,
            final int bufferSize, final ByteArrayTransformer transformer) throws IOException {
        final byte[] buffer = new byte[bufferSize];
        try {
            int len;
            while ((len = inputStream.read(buffer)) > 0) {
                final byte[] receivedBytes = Arrays.copyOf(buffer, len);
                final byte[] transformedBytes = transformer.transform(receivedBytes);
                outputStream.write(transformedBytes);
            }
        } finally {
            // Zero the buffer
            Arrays.fill(buffer, (byte) 0);
            try {
                inputStream.close();
            } catch (IOException ex) {
                // ignore, but dump stacktrace to syserr
                ex.printStackTrace();
            }
        }
    }

    interface ByteArrayTransformer {
        byte[] transform(byte[] bytes);
    }

}
