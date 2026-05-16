package com.packetanalyzer.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class DpiEngine {
    private static final int LOAD_BALANCER_COUNT = 2;
    private static final int FPS_PER_LB = 2;
    private static final int FP_COUNT = LOAD_BALANCER_COUNT * FPS_PER_LB;
    private static final int QUEUE_SIZE = 10_000;

    private final BlockingRules rules;
    private final DpiStats stats = new DpiStats();

    DpiEngine(BlockingRules rules) {
        this.rules = rules;
    }

    DpiStats process(Path inputFile, Path outputFile) throws IOException, InterruptedException {
        List<ThreadSafeQueue<PacketJob>> fpQueues = new ArrayList<>();
        List<Thread> fpThreads = new ArrayList<>();
        ThreadSafeQueue<ProcessedPacket> outputQueue = new ThreadSafeQueue<>(QUEUE_SIZE);

        try (PcapReader reader = new PcapReader(inputFile)) {
            OrderedPcapWriter orderedWriter = new OrderedPcapWriter(outputFile, reader.globalHeader(), outputQueue);
            Thread writerThread = new Thread(orderedWriter, "pcap-writer");
            writerThread.start();

            for (int i = 0; i < FP_COUNT; i++) {
                ThreadSafeQueue<PacketJob> queue = new ThreadSafeQueue<>(QUEUE_SIZE);
                fpQueues.add(queue);
                Thread thread = new Thread(new FastPathProcessor(i, queue, outputQueue, rules, stats), "fp-" + i);
                fpThreads.add(thread);
                thread.start();
            }

            LBManager lbManager = new LBManager(LOAD_BALANCER_COUNT, FPS_PER_LB, fpQueues);
            lbManager.startAll();

            System.out.println("[DPI] Pipeline: Reader -> 2 LoadBalancers -> 4 FP threads -> Ordered PCAP Writer");
            System.out.println("[DPI] Processing packets...");
            readAndDispatch(reader, lbManager);

            lbManager.stopAll();
            for (Thread thread : fpThreads) {
                thread.join();
            }

            outputQueue.push(ProcessedPacket.POISON);
            writerThread.join();
            if (orderedWriter.failure() != null) {
                throw orderedWriter.failure();
            }

            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            System.out.println("[DPI] Load balancers dispatched " + lbStats.totalDispatched()
                + " of " + lbStats.totalReceived() + " received packets");
        }

        return stats;
    }

    private void readAndDispatch(PcapReader reader, LBManager lbManager)
        throws IOException, InterruptedException {
        long sequence = 0;
        Optional<RawPacket> next;
        while ((next = reader.readNextPacket()).isPresent()) {
            RawPacket raw = next.get();
            stats.totalPackets.increment();

            Optional<ParsedPacket> maybeParsed = PacketParser.parse(raw);
            if (maybeParsed.isEmpty()) {
                continue;
            }

            ParsedPacket parsed = maybeParsed.get();
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                continue;
            }

            FiveTuple tuple = new FiveTuple(parsed.srcIp, parsed.dstIp, parsed.srcPort, parsed.dstPort, parsed.protocol);
            PacketJob job = new PacketJob(++sequence, raw, parsed, tuple);
            lbManager.getLBForPacket(tuple).getInputQueue().push(job);
        }
    }
}
