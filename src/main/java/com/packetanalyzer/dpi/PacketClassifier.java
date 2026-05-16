package com.packetanalyzer.dpi;

final class PacketClassifier {
    private PacketClassifier() {
    }

    static void classify(RawPacket raw, ParsedPacket parsed, Flow flow) {
        if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)
            && flow.sni.isEmpty()
            && parsed.hasTcp
            && parsed.dstPort == 443
            && parsed.payloadLength > 5) {
            SniExtractor.extract(raw.data, parsed.payloadOffset, parsed.payloadLength).ifPresent(sni -> {
                flow.sni = sni;
                flow.appType = AppType.fromDomain(sni);
            });
        }

        if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)
            && flow.sni.isEmpty()
            && parsed.hasTcp
            && parsed.dstPort == 80
            && parsed.payloadLength > 0) {
            HttpHostExtractor.extract(raw.data, parsed.payloadOffset, parsed.payloadLength).ifPresent(host -> {
                flow.sni = host;
                flow.appType = AppType.fromDomain(host);
            });
        }

        if (flow.appType == AppType.UNKNOWN && (parsed.dstPort == 53 || parsed.srcPort == 53)) {
            flow.appType = AppType.DNS;
        }

        if (flow.appType == AppType.UNKNOWN) {
            if (parsed.dstPort == 443) {
                flow.appType = AppType.HTTPS;
            } else if (parsed.dstPort == 80) {
                flow.appType = AppType.HTTP;
            }
        }
    }
}
