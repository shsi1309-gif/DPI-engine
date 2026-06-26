package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class BlockingRules {
    private final Set<String> blockedIps = new HashSet<>();
    private final Set<String> blockedDestinationIps = new HashSet<>();
    private final EnumSet<AppType> blockedApps = EnumSet.noneOf(AppType.class);
    private final List<String> blockedDomains = new ArrayList<>();

    void blockIp(String ip) {
        blockedIps.add(PcapUtil.normalizeIp(ip));
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    void blockDestinationIp(String ip) {
        blockedDestinationIps.add(PcapUtil.normalizeIp(ip));
        System.out.println("[Rules] Blocked destination IP: " + ip);
    }

    void blockApp(String appName) {
        AppType app = AppType.fromDisplayName(appName);
        if (app == null) {
            throw new IllegalArgumentException("Unknown app: " + appName);
        }
        blockedApps.add(app);
        System.out.println("[Rules] Blocked app: " + app.displayName());
    }

    void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase(Locale.ROOT));
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    boolean isBlocked(String srcIp, String dstIp, AppType app, String domain) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedDestinationIps.contains(dstIp)) return true;
        if (blockedApps.contains(app)) return true;

        String lowerDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
        for (String blockedDomain : blockedDomains) {
            if (lowerDomain.contains(blockedDomain)) {
                return true;
            }
        }

        return false;
    }
}
