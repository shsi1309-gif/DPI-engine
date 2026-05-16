package com.packetanalyzer.dpi;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

final class PcapUtil {
    static final int PROTOCOL_TCP = 6;
    static final int PROTOCOL_UDP = 17;
    static final int ETHERTYPE_IPV4 = 0x0800;

    private PcapUtil() {
    }

    static int readUnsignedShortBE(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    static long readUnsignedInt(ByteBuffer buffer) {
        return Integer.toUnsignedLong(buffer.getInt());
    }

    static void putUnsignedInt(ByteBuffer buffer, long value) {
        buffer.putInt((int) value);
    }

    static String ipToString(int ip) {
        return (ip & 0xff) + "."
            + ((ip >>> 8) & 0xff) + "."
            + ((ip >>> 16) & 0xff) + "."
            + ((ip >>> 24) & 0xff);
    }

    static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }

        int result = 0;
        for (int i = 0; i < parts.length; i++) {
            int octet = Integer.parseInt(parts[i]);
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            }
            result |= octet << (i * 8);
        }
        return result;
    }

    static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTOCOL_TCP -> "TCP";
            case PROTOCOL_UDP -> "UDP";
            case 1 -> "ICMP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    static ByteOrder pcapByteOrder(int magic) {
        if (magic == 0xa1b2c3d4) {
            return ByteOrder.BIG_ENDIAN;
        }
        if (magic == 0xd4c3b2a1) {
            return ByteOrder.LITTLE_ENDIAN;
        }
        throw new IllegalArgumentException("Invalid PCAP magic number: 0x" + Integer.toHexString(magic));
    }
}
