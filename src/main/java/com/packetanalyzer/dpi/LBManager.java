package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.List;

final class LBManager {
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();
    private final int fpsPerLb;

    LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        if (numLbs <= 0 || fpsPerLb <= 0) {
            throw new IllegalArgumentException("LB and FP counts must be positive");
        }
        if (fpQueues.size() != numLbs * fpsPerLb) {
            throw new IllegalArgumentException("FP queue count must equal numLbs * fpsPerLb");
        }

        this.fpsPerLb = fpsPerLb;
        for (int lbId = 0; lbId < numLbs; lbId++) {
            int fpStartId = lbId * fpsPerLb;
            int fpEndId = fpStartId + fpsPerLb;
            loadBalancers.add(new LoadBalancer(lbId, fpQueues.subList(fpStartId, fpEndId), fpStartId));
        }
    }

    void startAll() {
        for (LoadBalancer lb : loadBalancers) {
            lb.start();
        }
    }

    void stopAll() throws InterruptedException {
        for (LoadBalancer lb : loadBalancers) {
            lb.stop();
        }
        for (LoadBalancer lb : loadBalancers) {
            lb.awaitStopped();
        }
    }

    LoadBalancer getLBForPacket(FiveTuple tuple) {
        int lbIndex = Math.floorMod(Math.floorDiv(tuple.hashCode(), fpsPerLb), loadBalancers.size());
        return loadBalancers.get(lbIndex);
    }

    LoadBalancer getLB(int id) {
        return loadBalancers.get(id);
    }

    int getNumLBs() {
        return loadBalancers.size();
    }

    AggregatedStats getAggregatedStats() {
        long totalReceived = 0;
        long totalDispatched = 0;
        for (LoadBalancer lb : loadBalancers) {
            LoadBalancer.LBStats stats = lb.getStats();
            totalReceived += stats.packetsReceived();
            totalDispatched += stats.packetsDispatched();
        }
        return new AggregatedStats(totalReceived, totalDispatched);
    }

    int getFpsPerLb() {
        return fpsPerLb;
    }

    record AggregatedStats(long totalReceived, long totalDispatched) {
    }
}
