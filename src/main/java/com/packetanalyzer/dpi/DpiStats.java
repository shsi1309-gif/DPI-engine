package com.packetanalyzer.dpi;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

final class DpiStats {
    final LongAdder totalPackets = new LongAdder();
    final LongAdder forwarded = new LongAdder();
    final LongAdder dropped = new LongAdder();
    final ConcurrentHashMap<FiveTuple, Flow> flows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<AppType, LongAdder> appStats = new ConcurrentHashMap<>();

    void incrementApp(AppType appType) {
        appStats.computeIfAbsent(appType, ignored -> new LongAdder()).increment();
    }

    EnumMap<AppType, Long> appStatsSnapshot() {
        EnumMap<AppType, Long> snapshot = new EnumMap<>(AppType.class);
        for (Map.Entry<AppType, LongAdder> entry : appStats.entrySet()) {
            snapshot.put(entry.getKey(), entry.getValue().sum());
        }
        return snapshot;
    }
}
