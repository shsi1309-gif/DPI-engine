package com.packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

final class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {
    }

    static Optional<String> extract(byte[] data, int offset, int length) {
        if (!isTlsClientHello(data, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        int cursor = offset + 5;
        cursor += 4;
        cursor += 2;
        cursor += 32;

        if (cursor >= end) return Optional.empty();
        int sessionIdLength = data[cursor] & 0xff;
        cursor += 1 + sessionIdLength;

        if (cursor + 2 > end) return Optional.empty();
        int cipherSuitesLength = PcapUtil.readUnsignedShortBE(data, cursor);
        cursor += 2 + cipherSuitesLength;

        if (cursor >= end) return Optional.empty();
        int compressionMethodsLength = data[cursor] & 0xff;
        cursor += 1 + compressionMethodsLength;

        if (cursor + 2 > end) return Optional.empty();
        int extensionsLength = PcapUtil.readUnsignedShortBE(data, cursor);
        cursor += 2;

        int extensionsEnd = Math.min(end, cursor + extensionsLength);
        while (cursor + 4 <= extensionsEnd) {
            int extensionType = PcapUtil.readUnsignedShortBE(data, cursor);
            int extensionLength = PcapUtil.readUnsignedShortBE(data, cursor + 2);
            cursor += 4;

            if (cursor + extensionLength > extensionsEnd) {
                break;
            }

            if (extensionType == EXTENSION_SNI) {
                return parseSniExtension(data, cursor, extensionLength);
            }

            cursor += extensionLength;
        }

        return Optional.empty();
    }

    private static boolean isTlsClientHello(byte[] data, int offset, int length) {
        if (length < 9 || offset < 0 || offset + length > data.length) return false;
        if ((data[offset] & 0xff) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = PcapUtil.readUnsignedShortBE(data, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLength = PcapUtil.readUnsignedShortBE(data, offset + 3);
        if (recordLength > length - 5) return false;

        return (data[offset + 5] & 0xff) == HANDSHAKE_CLIENT_HELLO;
    }

    private static Optional<String> parseSniExtension(byte[] data, int offset, int extensionLength) {
        if (extensionLength < 5) return Optional.empty();

        int sniListLength = PcapUtil.readUnsignedShortBE(data, offset);
        if (sniListLength < 3) return Optional.empty();

        int sniType = data[offset + 2] & 0xff;
        int sniLength = PcapUtil.readUnsignedShortBE(data, offset + 3);
        if (sniType != SNI_TYPE_HOSTNAME || sniLength > extensionLength - 5) {
            return Optional.empty();
        }

        return Optional.of(new String(data, offset + 5, sniLength, StandardCharsets.US_ASCII));
    }
}
