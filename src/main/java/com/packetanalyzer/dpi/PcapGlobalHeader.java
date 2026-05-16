package com.packetanalyzer.dpi;

import java.nio.ByteOrder;

final class PcapGlobalHeader {
    final byte[] rawBytes;
    final ByteOrder byteOrder;
    final int versionMajor;
    final int versionMinor;
    final long snaplen;
    final long network;

    PcapGlobalHeader(byte[] rawBytes, ByteOrder byteOrder, int versionMajor, int versionMinor, long snaplen, long network) {
        this.rawBytes = rawBytes;
        this.byteOrder = byteOrder;
        this.versionMajor = versionMajor;
        this.versionMinor = versionMinor;
        this.snaplen = snaplen;
        this.network = network;
    }
}
