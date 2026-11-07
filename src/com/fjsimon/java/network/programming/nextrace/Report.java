package com.fjsimon.java.network.programming.nextrace;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;


/** Exports connection/host reports to CSV, mirroring sniffnet's report page. */
public final class Report {

    private Report() {}

    public static void writeConnections(String path, Snapshot snap)
            throws IOException {
        List<Connection> conns = snap.getConnections();
        try (BufferedWriter w = Files.newBufferedWriter(
                Path.of(path), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            w.write("local,local_port,remote,remote_port,protocol,service,direction,"
                    + "tx_packets,rx_packets,tx_bytes,rx_bytes,total_bytes\n");
            for (Connection c : conns) {
                w.write(String.join(",",
                        c.localIp.getHostAddress(),
                        port(c.localPort),
                        c.remoteIp.getHostAddress(),
                        port(c.remotePort),
                        c.protocol.name(),
                        c.service == null ? "" : c.service,
                        c.direction.name(),
                        Long.toString(c.txPackets),
                        Long.toString(c.rxPackets),
                        Long.toString(c.txBytes),
                        Long.toString(c.rxBytes),
                        Long.toString(c.totalBytes())));
                w.newLine();
            }
        }
    }

    public static void writeHosts(String path, Snapshot snap) throws IOException {
        List<HostStat> hosts = snap.getHosts();
        try (BufferedWriter w = Files.newBufferedWriter(
                Path.of(path), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            w.write("ip,local,asn,org,country,tx_packets,rx_packets,tx_bytes,rx_bytes,total_bytes\n");
            for (HostStat h : hosts) {
                w.write(String.join(",",
                        h.ip.getHostAddress(),
                        Boolean.toString(h.local),
                        h.asn == null ? "" : h.asn,
                        h.org == null ? "" : "\"" + h.org.replace("\"", "\"\"") + "\"",
                        h.country == null ? "" : h.country,
                        Long.toString(h.txPackets),
                        Long.toString(h.rxPackets),
                        Long.toString(h.txBytes),
                        Long.toString(h.rxBytes),
                        Long.toString(h.totalBytes())));
                w.newLine();
            }
        }
    }

    /** Human-readable summary printed to stdout after capture. */
    public static void printSummary(Snapshot snap, String deviceLabel) {
        System.out.println("==== sniffnet (java) report ====");
        System.out.println("device            : " + deviceLabel);
        System.out.println("captured packets  : " + snap.getTotalPackets());
        System.out.println("captured bytes    : " + Format.bytes(snap.getTotalBytes()));
        System.out.println("dropped packets   : " + snap.getDroppedPackets());
        System.out.println("duration          : " + Format.duration(snap.uptimeSeconds()));
        System.out.println();
        System.out.println("--- traffic per protocol ---");
        for (var proto : Protocol.values()) {
            int idx = proto.ordinal();
            System.out.printf("  %-6s %14s  %10d packets%n",
                    proto.name(), Format.bytes(snap.getProtoBytes()[idx]), snap.getProtoBytes()[idx]);
        }
        System.out.println();
        System.out.println("--- top connections ---");
        int n = Math.min(20, snap.getConnections().size());
        System.out.printf("  %-24s %-24s %-6s %-12s %-10s %12s%n",
                "local", "remote", "proto", "service", "dir", "bytes");
        for (int i = 0; i < n; i++) {
            Connection c = snap.getConnections().get(i);
            System.out.printf("  %-24s %-24s %-6s %-12s %-10s %12s%n",
                    addrPort(c.localIp, c.localPort),
                    addrPort(c.remoteIp, c.remotePort),
                    c.protocol.name(),
                    c.service == null ? "-" : c.service,
                    c.direction.name().toLowerCase(),
                    Format.bytes(c.totalBytes()));
        }
        System.out.println();
        System.out.println("--- top hosts ---");
        int m = Math.min(20, snap.getHosts().size());
        System.out.printf("  %-24s %-8s %-4s %12s %12s%n",
                "ip", "asn", "cc", "packets", "bytes");
        for (int i = 0; i < m; i++) {
            HostStat h = snap.getHosts().get(i);
            System.out.printf("  %-24s %-8s %-4s %12d %12s%n",
                    h.ip.getHostAddress(),
                    h.asn == null ? "-" : h.asn,
                    h.country == null ? "-" : h.country,
                    h.txPackets + h.rxPackets,
                    Format.bytes(h.totalBytes()));
        }
        System.out.println("===============================");
    }

    private static String port(int p) {
        return p < 0 ? "-" : Integer.toString(p);
    }

    private static String addrPort(java.net.InetAddress ip, int port) {
        String s = ip.getHostAddress();
        return port < 0 ? s : s + ":" + port;
    }
}