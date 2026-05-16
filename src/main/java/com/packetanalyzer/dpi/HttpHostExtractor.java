package com.packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

final class HttpHostExtractor {
    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    private HttpHostExtractor() {
    }

    static Optional<String> extract(byte[] data, int offset, int length) {
        if (!isHttpRequest(data, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        for (int i = offset; i + 5 < end; i++) {
            if (equalsIgnoreCase(data[i], 'h')
                && equalsIgnoreCase(data[i + 1], 'o')
                && equalsIgnoreCase(data[i + 2], 's')
                && equalsIgnoreCase(data[i + 3], 't')
                && data[i + 4] == ':') {
                int start = i + 5;
                while (start < end && (data[start] == ' ' || data[start] == '\t')) {
                    start++;
                }

                int hostEnd = start;
                while (hostEnd < end && data[hostEnd] != '\r' && data[hostEnd] != '\n') {
                    hostEnd++;
                }

                if (hostEnd > start) {
                    String host = new String(data, start, hostEnd - start, StandardCharsets.US_ASCII);
                    int colon = host.indexOf(':');
                    return Optional.of(colon >= 0 ? host.substring(0, colon) : host);
                }
            }
        }

        return Optional.empty();
    }

    private static boolean isHttpRequest(byte[] data, int offset, int length) {
        if (length < 4) return false;
        for (String method : METHODS) {
            boolean matches = true;
            for (int i = 0; i < 4; i++) {
                if (data[offset + i] != method.charAt(i)) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
        return false;
    }

    private static boolean equalsIgnoreCase(byte value, char expected) {
        int actual = value & 0xff;
        return actual == expected || actual == Character.toUpperCase(expected);
    }
}
