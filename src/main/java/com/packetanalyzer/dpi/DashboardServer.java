package com.packetanalyzer.dpi;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DashboardServer {
    private static final int DEFAULT_PORT = 8080;
    private static final Path DEFAULT_INPUT = Path.of("test_dpi.pcap");
    private static final Path DEFAULT_OUTPUT = Path.of("build", "dashboard-filtered.pcap");
    private static final Path UPLOAD_DIR = Path.of("build", "uploads");
    private static volatile Path currentInput = DEFAULT_INPUT;
    private static final Pattern JSON_STRING_PATTERN = Pattern.compile("\"((?:\\\\.|[^\"])*)\"");

    private DashboardServer() {
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/api/analyze", DashboardServer::handleAnalyze);
        server.createContext("/api/upload", DashboardServer::handleUpload);
        server.createContext("/api/health", DashboardServer::handleHealth);
        server.setExecutor(null);
        server.start();

        System.out.println("Dashboard API running at http://127.0.0.1:" + port);
        System.out.println("POST /api/analyze with {\"blockedApps\":[\"YouTube\"],\"blockedDomains\":[\"youtube.com\"],\"blockedIps\":[\"192.168.1.100\"]}");
        System.out.println("POST /api/upload with raw PCAP bytes and X-File-Name header");
    }

    private static void handleHealth(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendNoContent(exchange);
            return;
        }
        sendJson(exchange, 200, "{\"status\":\"ok\"}");
    }

    private static void handleAnalyze(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendNoContent(exchange);
            return;
        }
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Use POST\"}");
            return;
        }

        try {
            String body = readRequestBody(exchange);
            BlockRequest blockRequest = parseBlockRequest(body);
            String response = analyze(blockRequest);
            sendJson(exchange, 200, response);
        } catch (Exception ex) {
            sendJson(exchange, 500, "{\"error\":\"" + escapeJson(ex.getMessage()) + "\"}");
        }
    }

    private static void handleUpload(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendNoContent(exchange);
            return;
        }
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Use POST\"}");
            return;
        }

        try {
            String requestedName = exchange.getRequestHeaders().getFirst("X-File-Name");
            String fileName = sanitizeFileName(requestedName == null ? "uploaded.pcap" : requestedName);
            Files.createDirectories(UPLOAD_DIR);

            Path uploadedFile = UPLOAD_DIR.resolve(System.currentTimeMillis() + "-" + fileName);
            try (InputStream input = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(uploadedFile)) {
                input.transferTo(output);
            }

            if (Files.size(uploadedFile) == 0) {
                Files.deleteIfExists(uploadedFile);
                sendJson(exchange, 400, "{\"error\":\"Uploaded file is empty\"}");
                return;
            }

            currentInput = uploadedFile;
            String response = analyze(BlockRequest.empty());
            sendJson(exchange, 200, response);
        } catch (Exception ex) {
            sendJson(exchange, 500, "{\"error\":\"" + escapeJson(ex.getMessage()) + "\"}");
        }
    }

    private static synchronized String analyze(BlockRequest blockRequest) throws Exception {
        Path inputFile = currentInput;
        if (!Files.exists(inputFile)) {
            throw new IOException("Missing input PCAP: " + inputFile);
        }
        Files.createDirectories(DEFAULT_OUTPUT.getParent());

        BlockingRules rules = new BlockingRules();
        for (String app : blockRequest.blockedApps()) {
            if (!app.isBlank()) {
                rules.blockApp(app);
            }
        }
        for (String domain : blockRequest.blockedDomains()) {
            if (!domain.isBlank()) {
                rules.blockDomain(domain);
            }
        }
        for (String ip : blockRequest.blockedIps()) {
            if (!ip.isBlank()) {
                rules.blockIp(ip);
            }
        }

        DpiEngine engine = new DpiEngine(rules);
        DpiStats stats = engine.process(inputFile, DEFAULT_OUTPUT);
        List<WebsiteRow> websites = buildWebsiteRows(stats);

        long totalPackets = stats.totalPackets.sum();
        long blockedPackets = stats.dropped.sum();
        long forwardedPackets = stats.forwarded.sum();
        long blockedBytes = websites.stream()
            .filter(WebsiteRow::blocked)
            .mapToLong(WebsiteRow::bytes)
            .sum();

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"totals\":{");
        json.append("\"totalPackets\":").append(totalPackets).append(",");
        json.append("\"blockedPackets\":").append(blockedPackets).append(",");
        json.append("\"forwardedPackets\":").append(forwardedPackets).append(",");
        json.append("\"blockedBytes\":").append(blockedBytes);
        json.append("},");
        json.append("\"inputFile\":\"").append(escapeJson(inputFile.toString())).append("\",");
        json.append("\"outputFile\":\"").append(escapeJson(DEFAULT_OUTPUT.toString())).append("\",");
        json.append("\"websites\":[");
        for (int i = 0; i < websites.size(); i++) {
            if (i > 0) {
                json.append(",");
            }
            json.append(websites.get(i).toJson());
        }
        json.append("]}");
        return json.toString();
    }

    private static List<WebsiteRow> buildWebsiteRows(DpiStats stats) {
        List<WebsiteRow> rows = new ArrayList<>();
        for (Flow flow : stats.flows.values()) {
            if (flow.sni == null || flow.sni.isBlank()) {
                continue;
            }
            rows.add(new WebsiteRow(
                flow.sni,
                flow.appType.displayName(),
                categoryFor(flow.appType),
                PcapUtil.protocolToString(flow.tuple.protocol),
                PcapUtil.ipToString(flow.tuple.srcIp),
                PcapUtil.ipToString(flow.tuple.dstIp),
                flow.tuple.dstPort,
                flow.packets,
                flow.bytes,
                1,
                riskFor(flow.appType),
                flow.blocked
            ));
        }
        rows.sort(Comparator.comparing(WebsiteRow::domain));
        return rows;
    }

    private static String categoryFor(AppType appType) {
        return switch (appType) {
            case YOUTUBE, NETFLIX -> "Streaming";
            case FACEBOOK, INSTAGRAM, TWITTER, TIKTOK -> "Social";
            case GITHUB -> "Developer";
            case SPOTIFY -> "Audio";
            case DISCORD, TELEGRAM, WHATSAPP, ZOOM -> "Communication";
            case CLOUDFLARE -> "Infrastructure";
            case GOOGLE, AMAZON, MICROSOFT, APPLE -> "Platform";
            case DNS -> "Network";
            default -> "Web";
        };
    }

    private static String riskFor(AppType appType) {
        return switch (appType) {
            case NETFLIX, TIKTOK -> "High";
            case YOUTUBE, FACEBOOK, INSTAGRAM, TWITTER, DISCORD, TELEGRAM, WHATSAPP, ZOOM -> "Medium";
            default -> "Low";
        };
    }

    private static BlockRequest parseBlockRequest(String body) {
        return new BlockRequest(
            parseStringArray(body, "blockedApps", false),
            parseStringArray(body, "blockedDomains", true),
            parseStringArray(body, "blockedIps", false)
        );
    }

    private static List<String> parseStringArray(String body, String fieldName, boolean lowercase) {
        List<String> values = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL);
        Matcher arrayMatcher = pattern.matcher(body == null ? "" : body);
        if (!arrayMatcher.find()) {
            return values;
        }

        Matcher stringMatcher = JSON_STRING_PATTERN.matcher(arrayMatcher.group(1));
        while (stringMatcher.find()) {
            String value = unescapeJson(stringMatcher.group(1)).trim();
            values.add(lowercase ? value.toLowerCase(Locale.ROOT) : value);
        }
        return values;
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        try (InputStream input = exchange.getRequestBody()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void sendNoContent(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange.getResponseHeaders());
        exchange.sendResponseHeaders(204, -1);
        exchange.close();
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        addCorsHeaders(headers);
        headers.set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static void addCorsHeaders(Headers headers) {
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type, X-File-Name");
    }

    private static String sanitizeFileName(String rawName) {
        String decoded = URLDecoder.decode(rawName, StandardCharsets.UTF_8);
        String baseName = Path.of(decoded).getFileName().toString();
        String sanitized = baseName.replaceAll("[^A-Za-z0-9._-]", "_");
        if (sanitized.isBlank()) {
            return "uploaded.pcap";
        }
        return sanitized;
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private static String unescapeJson(String value) {
        return value.replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }

    private record BlockRequest(
        List<String> blockedApps,
        List<String> blockedDomains,
        List<String> blockedIps
    ) {
        static BlockRequest empty() {
            return new BlockRequest(List.of(), List.of(), List.of());
        }
    }

    private record WebsiteRow(
        String domain,
        String app,
        String category,
        String protocol,
        String sourceIp,
        String destinationIp,
        int port,
        long packets,
        long bytes,
        long flows,
        String risk,
        boolean blocked
    ) {
        String toJson() {
            return "{"
                + "\"id\":\"" + escapeJson(domain) + "\","
                + "\"domain\":\"" + escapeJson(domain) + "\","
                + "\"app\":\"" + escapeJson(app) + "\","
                + "\"category\":\"" + escapeJson(category) + "\","
                + "\"protocol\":\"" + escapeJson(protocol) + "\","
                + "\"sourceIp\":\"" + escapeJson(sourceIp) + "\","
                + "\"destinationIp\":\"" + escapeJson(destinationIp) + "\","
                + "\"port\":" + port + ","
                + "\"packets\":" + packets + ","
                + "\"bytes\":" + bytes + ","
                + "\"flows\":" + flows + ","
                + "\"risk\":\"" + escapeJson(risk) + "\","
                + "\"lastSeen\":\"From PCAP\","
                + "\"blocked\":" + blocked
                + "}";
        }
    }
}
