package com.packetanalyzer.dpi;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

final class PcapReader implements Closeable {
    private InputStream input;
    private PcapGlobalHeader globalHeader;

    PcapReader(Path path) throws IOException {
        input = Files.newInputStream(path);
        readGlobalHeader(path);
    }

    PcapGlobalHeader globalHeader() {
        return globalHeader;
    }

    Optional<RawPacket> readNextPacket() throws IOException {
        byte[] headerBytes = input.readNBytes(16);
        if (headerBytes.length == 0) {
            return Optional.empty();
        }
        if (headerBytes.length < 16) {
            throw new EOFException("Truncated PCAP packet header");
        }

        ByteBuffer buffer = ByteBuffer.wrap(headerBytes).order(globalHeader.byteOrder);
        PcapPacketHeader header = new PcapPacketHeader(
            PcapUtil.readUnsignedInt(buffer),
            PcapUtil.readUnsignedInt(buffer),
            PcapUtil.readUnsignedInt(buffer),
            PcapUtil.readUnsignedInt(buffer)
        );

        if (header.inclLen > globalHeader.snaplen || header.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + header.inclLen);
        }

        byte[] data = input.readNBytes((int) header.inclLen);
        if (data.length < header.inclLen) {
            throw new EOFException("Truncated PCAP packet data");
        }

        return Optional.of(new RawPacket(header, data));
    }

    private void readGlobalHeader(Path path) throws IOException {
        byte[] bytes = input.readNBytes(24);
        if (bytes.length < 24) {
            throw new EOFException("Could not read PCAP global header");
        }

        int magic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        ByteOrder order = PcapUtil.pcapByteOrder(magic);
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(order);
        buffer.getInt();

        globalHeader = new PcapGlobalHeader(
            bytes,
            order,
            Short.toUnsignedInt(buffer.getShort()),
            Short.toUnsignedInt(buffer.getShort()),
            skipThiszoneAndReadSnaplen(buffer),
            PcapUtil.readUnsignedInt(buffer)
        );

        System.out.println("Opened PCAP file: " + path);
        System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
        System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
        System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));
    }

    private static long skipThiszoneAndReadSnaplen(ByteBuffer buffer) {
        buffer.getInt();
        buffer.getInt();
        return PcapUtil.readUnsignedInt(buffer);
    }

    @Override
    public void close() throws IOException {
        if (input != null) {
            input.close();
        }
    }
}
