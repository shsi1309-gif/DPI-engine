package com.packetanalyzer.dpi;

final class PcapPacketHeader {
    final long tsSec;
    final long tsUsec;
    final long inclLen;
    final long origLen;

    PcapPacketHeader(long tsSec, long tsUsec, long inclLen, long origLen) {
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
    }
}
