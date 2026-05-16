package com.packetanalyzer.dpi;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        Path inputFile = Path.of(args[0]);
        Path outputFile = Path.of(args[1]);
        BlockingRules rules = new BlockingRules();

        try {
            parseOptions(args, rules);
            run(inputFile, outputFile, rules);
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            System.exit(1);
        }
    }

    private static void run(Path inputFile, Path outputFile, BlockingRules rules) throws Exception {
        printBanner();

        DpiEngine engine = new DpiEngine(rules);
        DpiStats stats = engine.process(inputFile, outputFile);
        printReport(
            stats.totalPackets.sum(),
            stats.forwarded.sum(),
            stats.dropped.sum(),
            stats.flows,
            stats.appStatsSnapshot(),
            outputFile
        );
    }

    private static void parseOptions(String[] args, BlockingRules rules) {
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if ("--block-ip".equals(arg) && i + 1 < args.length) {
                rules.blockIp(args[++i]);
            } else if ("--block-app".equals(arg) && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if ("--block-domain".equals(arg) && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            } else {
                throw new IllegalArgumentException("Unknown or incomplete option: " + arg);
            }
        }
    }

    private static void printUsage() {
        System.out.println("""
            DPI Engine - Deep Packet Inspection System
            ==========================================

            Usage: java -jar build/dpi-engine.jar <input.pcap> <output.pcap> [options]

            Options:
              --block-ip <ip>        Block traffic from source IP
              --block-app <app>      Block application (YouTube, Facebook, etc.)
              --block-domain <dom>   Block domain (substring match)

            Example:
              java -jar build/dpi-engine.jar capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
            """);
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("==============================================================");
        System.out.println("                    DPI ENGINE v1.0 (Java)");
        System.out.println("==============================================================");
        System.out.println();
    }

    private static void printReport(
        long totalPackets,
        long forwarded,
        long dropped,
        Map<FiveTuple, Flow> flows,
        EnumMap<AppType, Long> appStats,
        Path outputFile
    ) {
        System.out.println();
        System.out.println("==============================================================");
        System.out.println("                      PROCESSING REPORT");
        System.out.println("==============================================================");
        System.out.printf("Total Packets:      %10d%n", totalPackets);
        System.out.printf("Forwarded:          %10d%n", forwarded);
        System.out.printf("Dropped:            %10d%n", dropped);
        System.out.printf("Active Flows:       %10d%n", flows.size());
        System.out.println("--------------------------------------------------------------");
        System.out.println("                    APPLICATION BREAKDOWN");
        System.out.println("--------------------------------------------------------------");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
        sortedApps.sort(Map.Entry.<AppType, Long>comparingByValue(Comparator.reverseOrder()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = totalPackets == 0 ? 0 : 100.0 * entry.getValue() / totalPackets;
            int barLength = (int) (pct / 5);
            String bar = "#".repeat(barLength);
            System.out.printf("%-15s %8d %5.1f%% %-20s%n",
                entry.getKey().displayName(),
                entry.getValue(),
                pct,
                bar);
        }

        System.out.println("==============================================================");
        System.out.println();
        System.out.println("[Detected Applications/Domains]");

        Map<String, AppType> uniqueDomains = new HashMap<>();
        for (Flow flow : flows.values()) {
            if (!flow.sni.isEmpty()) {
                uniqueDomains.put(flow.sni, flow.appType);
            }
        }
        uniqueDomains.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().displayName()));

        System.out.println();
        System.out.println("Output written to: " + outputFile);
    }
}
