package com.packetanalyzer.dpi;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

final class PcapWriter implements Closeable {
    private final OutputStream output;
    private final PcapGlobalHeader globalHeader;

    PcapWriter(Path path, PcapGlobalHeader globalHeader) throws IOException {
        this.output = Files.newOutputStream(path);
        this.globalHeader = globalHeader;
        output.write(globalHeader.rawBytes);
    }

    void write(RawPacket packet) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(16).order(globalHeader.byteOrder);
        PcapUtil.putUnsignedInt(header, packet.header.tsSec);
        PcapUtil.putUnsignedInt(header, packet.header.tsUsec);
        PcapUtil.putUnsignedInt(header, packet.data.length);
        PcapUtil.putUnsignedInt(header, packet.data.length);
        output.write(header.array());
        output.write(packet.data);
    }

    @Override
    public void close() throws IOException {
        output.close();
    }
}
