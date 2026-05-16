package com.packetanalyzer.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.TreeMap;

final class OrderedPcapWriter implements Runnable {
    private final Path outputFile;
    private final PcapGlobalHeader globalHeader;
    private final ThreadSafeQueue<ProcessedPacket> outputQueue;
    private final TreeMap<Long, ProcessedPacket> pending = new TreeMap<>();
    private IOException failure;
    private long nextSequence = 1;

    OrderedPcapWriter(Path outputFile, PcapGlobalHeader globalHeader, ThreadSafeQueue<ProcessedPacket> outputQueue) {
        this.outputFile = outputFile;
        this.globalHeader = globalHeader;
        this.outputQueue = outputQueue;
    }

    IOException failure() {
        return failure;
    }

    @Override
    public void run() {
        try (PcapWriter writer = new PcapWriter(outputFile, globalHeader)) {
            while (true) {
                ProcessedPacket packet = outputQueue.pop().orElse(null);
                if (packet == null) {
                    return;
                }
                if (packet.isPoison()) {
                    flushReady(writer);
                    return;
                }
                pending.put(packet.sequence, packet);
                flushReady(writer);
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (IOException ex) {
            failure = ex;
        }
    }

    private void flushReady(PcapWriter writer) throws IOException {
        while (true) {
            ProcessedPacket packet = pending.remove(nextSequence);
            if (packet == null) {
                return;
            }
            if (packet.forward) {
                writer.write(packet.raw);
            }
            nextSequence++;
        }
    }
}
