package com.packetanalyzer.dpi;

final class FastPathProcessor implements Runnable {
    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ThreadSafeQueue<ProcessedPacket> outputQueue;
    private final BlockingRules rules;
    private final DpiStats stats;

    FastPathProcessor(
        int fpId,
        ThreadSafeQueue<PacketJob> inputQueue,
        ThreadSafeQueue<ProcessedPacket> outputQueue,
        BlockingRules rules,
        DpiStats stats
    ) {
        this.fpId = fpId;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.rules = rules;
        this.stats = stats;
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
                    return;
                }
                process(job);
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private void process(PacketJob job) throws InterruptedException {
        Flow flow = stats.flows.computeIfAbsent(job.tuple, Flow::new);
        flow.packets++;
        flow.bytes += job.raw.data.length;

        if (job.parsed.hasUdp && (job.parsed.srcPort == 53 || job.parsed.dstPort == 53)) {
            for (DnsNameExtractor.DnsRecord record : DnsNameExtractor.extract(
                job.raw.data,
                job.parsed.payloadOffset,
                job.parsed.payloadLength
            )) {
                stats.dnsNamesByIp.putIfAbsent(record.ip(), record.domain());
            }
        }

        PacketClassifier.classify(job.raw, job.parsed, flow);
        applyDnsNameFallback(flow);

        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(job.tuple.srcIp, job.tuple.dstIp, flow.appType, flow.sni);
            if (flow.blocked) {
                System.out.println("[FP-" + fpId + " BLOCKED] "
                    + job.parsed.srcIp + " -> " + job.parsed.dstIp
                    + " (" + flow.appType.displayName()
                    + (flow.sni.isEmpty() ? "" : ": " + flow.sni)
                    + ")");
            }
        }

        stats.incrementApp(flow.appType);

        if (flow.blocked) {
            stats.dropped.increment();
            outputQueue.push(new ProcessedPacket(job.sequence, null, false));
        } else {
            stats.forwarded.increment();
            outputQueue.push(new ProcessedPacket(job.sequence, job.raw, true));
        }
    }

    private void applyDnsNameFallback(Flow flow) {
        if (flow.sni != null && !flow.sni.isBlank()) {
            return;
        }

        String domain = stats.dnsNamesByIp.getOrDefault(flow.tuple.dstIp, "");
        if (domain.isBlank()) {
            domain = stats.dnsNamesByIp.getOrDefault(flow.tuple.srcIp, "");
        }
        if (domain.isBlank()) {
            return;
        }

        flow.sni = domain;
        flow.appType = AppType.fromDomain(domain);
    }
}
