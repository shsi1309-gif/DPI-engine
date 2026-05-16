package com.packetanalyzer.dpi;

final class ProcessedPacket {
    static final ProcessedPacket POISON = new ProcessedPacket(-1, null, false);

    final long sequence;
    final RawPacket raw;
    final boolean forward;

    ProcessedPacket(long sequence, RawPacket raw, boolean forward) {
        this.sequence = sequence;
        this.raw = raw;
        this.forward = forward;
    }

    boolean isPoison() {
        return sequence < 0;
    }
}
