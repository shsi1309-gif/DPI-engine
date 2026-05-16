package com.packetanalyzer.dpi;

final class PacketJob {
    static final PacketJob POISON = new PacketJob(-1, null, null, null);

    final long sequence;
    final RawPacket raw;
    final ParsedPacket parsed;
    final FiveTuple tuple;

    PacketJob(long sequence, RawPacket raw, ParsedPacket parsed, FiveTuple tuple) {
        this.sequence = sequence;
        this.raw = raw;
        this.parsed = parsed;
        this.tuple = tuple;
    }

    boolean isPoison() {
        return sequence < 0;
    }
}
