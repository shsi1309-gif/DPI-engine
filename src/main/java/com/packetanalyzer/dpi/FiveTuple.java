package com.packetanalyzer.dpi;

import java.util.Objects;

final class FiveTuple {
    final String srcIp;
    final String dstIp;
    final int srcPort;
    final int dstPort;
    final int protocol;

    FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof FiveTuple tuple)) return false;
        return Objects.equals(srcIp, tuple.srcIp)
            && Objects.equals(dstIp, tuple.dstIp)
            && srcPort == tuple.srcPort
            && dstPort == tuple.dstPort
            && protocol == tuple.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return srcIp + ":" + srcPort
            + " -> " + dstIp + ":" + dstPort
            + " (" + PcapUtil.protocolToString(protocol) + ")";
    }
}
