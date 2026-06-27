package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class DnsNameExtractor {
    private static final int DNS_HEADER_LEN = 12;
    private static final int TYPE_A = 1;
    private static final int TYPE_CNAME = 5;
    private static final int TYPE_AAAA = 28;
    private static final int CLASS_IN = 1;

    private DnsNameExtractor() {
    }

    static List<DnsRecord> extract(byte[] data, int offset, int length) {
        List<DnsRecord> records = new ArrayList<>();
        if (length < DNS_HEADER_LEN || offset < 0 || offset + length > data.length) {
            return records;
        }

        int end = offset + length;
        int flags = PcapUtil.readUnsignedShortBE(data, offset + 2);
        boolean response = (flags & 0x8000) != 0;
        if (!response) {
            return records;
        }

        int qdCount = PcapUtil.readUnsignedShortBE(data, offset + 4);
        int anCount = PcapUtil.readUnsignedShortBE(data, offset + 6);
        if (qdCount < 0 || anCount <= 0) {
            return records;
        }

        Cursor cursor = new Cursor(offset + DNS_HEADER_LEN);
        List<String> questionNames = new ArrayList<>();
        for (int i = 0; i < qdCount && cursor.position < end; i++) {
            String name = readName(data, offset, end, cursor);
            if (!name.isEmpty()) {
                questionNames.add(name);
            }
            if (cursor.position + 4 > end) {
                return records;
            }
            cursor.position += 4;
        }

        String latestName = questionNames.isEmpty() ? "" : questionNames.get(0);
        for (int i = 0; i < anCount && cursor.position < end; i++) {
            String answerName = readName(data, offset, end, cursor);
            if (cursor.position + 10 > end) {
                return records;
            }

            int type = PcapUtil.readUnsignedShortBE(data, cursor.position);
            int dnsClass = PcapUtil.readUnsignedShortBE(data, cursor.position + 2);
            int rdLength = PcapUtil.readUnsignedShortBE(data, cursor.position + 8);
            cursor.position += 10;
            if (cursor.position + rdLength > end) {
                return records;
            }

            String recordName = !answerName.isEmpty() ? answerName : latestName;
            if (dnsClass == CLASS_IN && type == TYPE_A && rdLength == 4 && !recordName.isEmpty()) {
                records.add(new DnsRecord(recordName, PcapUtil.ipv4ToString(data, cursor.position)));
                latestName = recordName;
            } else if (dnsClass == CLASS_IN && type == TYPE_AAAA && rdLength == 16 && !recordName.isEmpty()) {
                records.add(new DnsRecord(recordName, PcapUtil.ipv6ToString(data, cursor.position)));
                latestName = recordName;
            } else if (dnsClass == CLASS_IN && type == TYPE_CNAME) {
                Cursor cnameCursor = new Cursor(cursor.position);
                String cname = readName(data, offset, end, cnameCursor);
                if (!cname.isEmpty()) {
                    latestName = cname;
                }
            }

            cursor.position += rdLength;
        }

        return records;
    }

    private static String readName(byte[] data, int messageOffset, int end, Cursor cursor) {
        StringBuilder name = new StringBuilder();
        int position = cursor.position;
        int jumpedPosition = -1;
        int jumps = 0;

        while (position < end) {
            int len = data[position] & 0xff;
            if (len == 0) {
                position++;
                if (jumpedPosition < 0) {
                    cursor.position = position;
                }
                return normalizeName(name.toString());
            }

            if ((len & 0xc0) == 0xc0) {
                if (position + 1 >= end || ++jumps > 16) {
                    return "";
                }
                int pointer = ((len & 0x3f) << 8) | (data[position + 1] & 0xff);
                int target = messageOffset + pointer;
                if (target < messageOffset || target >= end) {
                    return "";
                }
                if (jumpedPosition < 0) {
                    jumpedPosition = position + 2;
                    cursor.position = jumpedPosition;
                }
                position = target;
                continue;
            }

            if ((len & 0xc0) != 0 || position + 1 + len > end) {
                return "";
            }
            if (!name.isEmpty()) {
                name.append('.');
            }
            name.append(new String(data, position + 1, len, java.nio.charset.StandardCharsets.US_ASCII));
            position += 1 + len;
        }

        return "";
    }

    private static String normalizeName(String name) {
        String normalized = name.toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    record DnsRecord(String domain, String ip) {
    }

    private static final class Cursor {
        int position;

        Cursor(int position) {
            this.position = position;
        }
    }
}
