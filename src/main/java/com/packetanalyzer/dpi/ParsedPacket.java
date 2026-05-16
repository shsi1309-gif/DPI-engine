package com.packetanalyzer.dpi;

final class ParsedPacket {
    long timestampSec;
    long timestampUsec;

    boolean hasIp;
    int srcIp;
    int dstIp;
    int protocol;
    int ttl;

    boolean hasTcp;
    boolean hasUdp;
    int srcPort;
    int dstPort;
    int tcpFlags;
    long seqNumber;
    long ackNumber;

    int payloadOffset;
    int payloadLength;
}
