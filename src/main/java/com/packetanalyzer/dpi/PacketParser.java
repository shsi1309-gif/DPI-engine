package com.packetanalyzer.dpi;

import java.util.Optional;

final class PacketParser {
    private static final int ETHERNET_HEADER_LEN = 14;
    private static final int MIN_IPV4_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    private PacketParser() {
    }

    static Optional<ParsedPacket> parse(RawPacket raw) {
        byte[] data = raw.data;
        if (data.length < ETHERNET_HEADER_LEN) {
            return Optional.empty();
        }

        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        int etherType = PcapUtil.readUnsignedShortBE(data, 12);
        int offset = ETHERNET_HEADER_LEN;
        if (etherType != PcapUtil.ETHERTYPE_IPV4) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = Math.max(0, data.length - offset);
            return Optional.of(parsed);
        }

        if (data.length < offset + MIN_IPV4_HEADER_LEN) {
            return Optional.empty();
        }

        int versionIhl = data[offset] & 0xff;
        int version = (versionIhl >>> 4) & 0x0f;
        int ihl = versionIhl & 0x0f;
        int ipHeaderLen = ihl * 4;
        if (version != 4 || ipHeaderLen < MIN_IPV4_HEADER_LEN || data.length < offset + ipHeaderLen) {
            return Optional.empty();
        }

        parsed.ttl = data[offset + 8] & 0xff;
        parsed.protocol = data[offset + 9] & 0xff;
        parsed.srcIp = readIpLittleDisplayOrder(data, offset + 12);
        parsed.dstIp = readIpLittleDisplayOrder(data, offset + 16);
        parsed.hasIp = true;
        offset += ipHeaderLen;

        if (parsed.protocol == PcapUtil.PROTOCOL_TCP) {
            if (!parseTcp(data, parsed, offset)) {
                return Optional.empty();
            }
            offset = parsed.payloadOffset;
        } else if (parsed.protocol == PcapUtil.PROTOCOL_UDP) {
            if (!parseUdp(data, parsed, offset)) {
                return Optional.empty();
            }
            offset = parsed.payloadOffset;
        }

        parsed.payloadLength = Math.max(0, data.length - offset);
        return Optional.of(parsed);
    }

    private static boolean parseTcp(byte[] data, ParsedPacket parsed, int offset) {
        if (data.length < offset + MIN_TCP_HEADER_LEN) {
            return false;
        }

        parsed.srcPort = PcapUtil.readUnsignedShortBE(data, offset);
        parsed.dstPort = PcapUtil.readUnsignedShortBE(data, offset + 2);
        parsed.seqNumber = readUnsignedIntBE(data, offset + 4);
        parsed.ackNumber = readUnsignedIntBE(data, offset + 8);
        int tcpHeaderLen = ((data[offset + 12] >>> 4) & 0x0f) * 4;
        parsed.tcpFlags = data[offset + 13] & 0xff;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || data.length < offset + tcpHeaderLen) {
            return false;
        }

        parsed.hasTcp = true;
        parsed.payloadOffset = offset + tcpHeaderLen;
        return true;
    }

    private static boolean parseUdp(byte[] data, ParsedPacket parsed, int offset) {
        if (data.length < offset + UDP_HEADER_LEN) {
            return false;
        }

        parsed.srcPort = PcapUtil.readUnsignedShortBE(data, offset);
        parsed.dstPort = PcapUtil.readUnsignedShortBE(data, offset + 2);
        parsed.hasUdp = true;
        parsed.payloadOffset = offset + UDP_HEADER_LEN;
        return true;
    }

    private static long readUnsignedIntBE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xff) << 24)
            | ((long) (data[offset + 1] & 0xff) << 16)
            | ((long) (data[offset + 2] & 0xff) << 8)
            | (long) (data[offset + 3] & 0xff);
    }

    private static int readIpLittleDisplayOrder(byte[] data, int offset) {
        return (data[offset] & 0xff)
            | ((data[offset + 1] & 0xff) << 8)
            | ((data[offset + 2] & 0xff) << 16)
            | ((data[offset + 3] & 0xff) << 24);
    }
}
