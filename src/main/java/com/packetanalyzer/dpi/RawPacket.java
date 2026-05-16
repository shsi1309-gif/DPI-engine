package com.packetanalyzer.dpi;

final class RawPacket {
    final PcapPacketHeader header;
    final byte[] data;

    RawPacket(PcapPacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }
}
