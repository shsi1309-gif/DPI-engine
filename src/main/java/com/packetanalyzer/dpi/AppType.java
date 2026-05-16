package com.packetanalyzer.dpi;

import java.util.Locale;

enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    String displayName() {
        return displayName;
    }

    static AppType fromDisplayName(String name) {
        for (AppType type : values()) {
            if (type.displayName.equals(name) || type.name().equalsIgnoreCase(name)) {
                return type;
            }
        }
        if ("Twitter/X".equalsIgnoreCase(name) || "Twitter".equalsIgnoreCase(name)) {
            return TWITTER;
        }
        return null;
    }

    static AppType fromDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return UNKNOWN;
        }

        String lower = domain.toLowerCase(Locale.ROOT);

        if (containsAny(lower, "youtube", "ytimg", "yt3.ggpht") || domainMatches(lower, "youtu.be")) return YOUTUBE;
        if (containsAny(lower, "google", "gstatic", "googleapis", "ggpht", "gvt1")) return GOOGLE;
        if (containsAny(lower, "facebook", "fbcdn", "fbsbx") || domainMatchesAny(lower, "fb.com", "meta.com")) return FACEBOOK;
        if (containsAny(lower, "instagram", "cdninstagram")) return INSTAGRAM;
        if (lower.contains("whatsapp") || domainMatches(lower, "wa.me")) return WHATSAPP;
        if (containsAny(lower, "twitter", "twimg") || domainMatchesAny(lower, "x.com", "t.co")) return TWITTER;
        if (containsAny(lower, "netflix", "nflxvideo", "nflximg")) return NETFLIX;
        if (containsAny(lower, "amazon", "amazonaws", "cloudfront", "aws")) return AMAZON;
        if (containsAny(lower, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) return MICROSOFT;
        if (containsAny(lower, "apple", "icloud", "mzstatic", "itunes")) return APPLE;
        if (lower.contains("telegram") || domainMatches(lower, "t.me")) return TELEGRAM;
        if (containsAny(lower, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) return TIKTOK;
        if (lower.contains("spotify") || domainMatches(lower, "scdn.co")) return SPOTIFY;
        if (lower.contains("zoom")) return ZOOM;
        if (containsAny(lower, "discord", "discordapp")) return DISCORD;
        if (containsAny(lower, "github", "githubusercontent")) return GITHUB;
        if (containsAny(lower, "cloudflare", "cf-")) return CLOUDFLARE;

        return HTTPS;
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean domainMatchesAny(String host, String... domains) {
        for (String domain : domains) {
            if (domainMatches(host, domain)) {
                return true;
            }
        }
        return false;
    }

    private static boolean domainMatches(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }
}
