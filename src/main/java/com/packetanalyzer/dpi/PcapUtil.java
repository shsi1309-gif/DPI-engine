package com.packetanalyzer.dpi;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Locale;

final class PcapUtil {
    static final int PROTOCOL_TCP = 6;
    static final int PROTOCOL_UDP = 17;
    static final int ETHERTYPE_IPV4 = 0x0800;
    static final int ETHERTYPE_IPV6 = 0x86dd;

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

    static String ipv4ToString(byte[] data, int offset) {
        return (data[offset] & 0xff) + "."
            + (data[offset + 1] & 0xff) + "."
            + (data[offset + 2] & 0xff) + "."
            + (data[offset + 3] & 0xff);
    }

    static String ipv6ToString(byte[] data, int offset) {
        byte[] address = Arrays.copyOfRange(data, offset, offset + 16);
        try {
            return InetAddress.getByAddress(address).getHostAddress().toLowerCase(Locale.ROOT);
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid IPv6 address bytes", ex);
        }
    }

    static String normalizeIp(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address.getHostAddress().toLowerCase(Locale.ROOT);
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid IP address: " + ip, ex);
        }
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
