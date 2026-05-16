package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class LoadBalancer implements Runnable {
    private static final int QUEUE_SIZE = 10_000;

    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(QUEUE_SIZE);
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private final long[] perFpCounts;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpQueues = List.copyOf(fpQueues);
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.perFpCounts = new long[numFps];
    }

    void start() {
        if (running.compareAndSet(false, true)) {
            thread = new Thread(this, "load-balancer-" + lbId);
            thread.start();
        }
    }

    void stop() throws InterruptedException {
        inputQueue.push(PacketJob.POISON);
    }

    void awaitStopped() throws InterruptedException {
        if (thread != null) {
            thread.join();
        }
    }

    ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    LBStats getStats() {
        List<Long> perFpPackets = new ArrayList<>();
        for (long count : perFpCounts) {
            perFpPackets.add(count);
        }
        return new LBStats(packetsReceived.get(), packetsDispatched.get(), perFpPackets);
    }

    int getId() {
        return lbId;
    }

    boolean isRunning() {
        return running.get();
    }

    @Override
    public void run() {
        try {
            while (true) {
                PacketJob job = inputQueue.pop().orElse(null);
                if (job == null) {
                    return;
                }
                if (job.isPoison()) {
                    for (ThreadSafeQueue<PacketJob> queue : fpQueues) {
                        queue.push(PacketJob.POISON);
                    }
                    return;
                }

                packetsReceived.incrementAndGet();
                int localFpIndex = selectFP(job.tuple);
                perFpCounts[localFpIndex]++;
                packetsDispatched.incrementAndGet();
                fpQueues.get(localFpIndex).push(job);
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } finally {
            running.set(false);
            System.out.println("[LB-" + lbId + "] closed");
        }
    }

    private int selectFP(FiveTuple tuple) {
        return Math.floorMod(tuple.hashCode(), numFps);
    }

    record LBStats(long packetsReceived, long packetsDispatched, List<Long> perFpPackets) {
    }
}
