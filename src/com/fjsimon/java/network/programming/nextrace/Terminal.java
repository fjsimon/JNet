package com.fjsimon.java.network.programming.nextrace;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Full-screen terminal dashboard using raw ANSI escape sequences.
 * Each frame is written atomically to eliminate flicker.
 */
public final class Terminal {

    private static final String[] BLOCKS = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};

    private static final String ESC = "\033[";
    private static final String RESET = ESC + "0m";
    private static final String BOLD = ESC + "1m";
    private static final String FG_BLACK = ESC + "30m";
    private static final String FG_WHITE = ESC + "97m";
    private static final String FG_YELLOW = ESC + "33m";
    private static final String FG_GREEN = ESC + "32m";
    private static final String FG_CYAN = ESC + "36m";
    private static final String BG_WHITE = ESC + "47m";
    private static final String HOME = ESC + "H";
    private static final String CLEAR_BELOW = ESC + "J";
    private static final String HIDE_CURSOR = ESC + "?25l";
    private static final String SHOW_CURSOR = ESC + "?25h";
    private static final String ALT_SCREEN_ON = ESC + "?1049h";
    private static final String ALT_SCREEN_OFF = ESC + "?1049l";

    private final ConnectionTracker tracker;
    private final String deviceLabel;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private volatile String statusMessage = "";

    public Terminal(ConnectionTracker tracker, String deviceLabel) {
        this.tracker = tracker;
        this.deviceLabel = deviceLabel;
    }

    public void run() {
        setupTerminal();
        Thread input = new Thread(this::inputLoop, "tui-input");
        input.setDaemon(true);
        input.start();
        try {
            while (running.get()) {
                int[] sz = terminalSize();
                int cols = sz[0], rows = sz[1];
                StringBuilder sb = new StringBuilder(cols * rows * 2);
                sb.append(HOME);
                render(sb, cols, rows);
                sb.append(CLEAR_BELOW);
                System.out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                System.out.flush();
                Thread.sleep(400);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("TUI error: " + e.getMessage());
        } finally {
            cleanupTerminal();
        }
    }

    // ── terminal setup / teardown ──────────────────────────────────────

    private void setupTerminal() {
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"sh", "-c", "stty raw -echo < /dev/tty"});
            p.waitFor();
        } catch (Exception ignored) {
        }
        System.out.print(ALT_SCREEN_ON + HIDE_CURSOR);
        System.out.flush();
    }

    private void cleanupTerminal() {
        System.out.print(SHOW_CURSOR + ALT_SCREEN_OFF + RESET);
        System.out.flush();
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"sh", "-c", "stty sane < /dev/tty"});
            p.waitFor();
        } catch (Exception ignored) {
        }
    }

    private static int[] terminalSize() {
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"sh", "-c", "stty size < /dev/tty"});
            String out;
            try (var in = p.getInputStream()) {
                out = new String(in.readAllBytes()).trim();
            }
            p.waitFor();
            String[] parts = out.split("\\s+");
            return new int[]{Integer.parseInt(parts[1]), Integer.parseInt(parts[0])};
        } catch (Exception e) {
            return new int[]{80, 24};
        }
    }

    // ── input ──────────────────────────────────────────────────────────

    private void inputLoop() {
        while (running.get()) {
            try {
                if (System.in.available() > 0) {
                    int c = System.in.read();
                    switch (c) {
                        case 'q': case 'x':
                            running.set(false);
                            break;
                        case 'p': case ' ':
                            boolean paused = !tracker.isPaused();
                            tracker.setPaused(paused);
                            statusMessage = paused ? "PAUSED" : "";
                            break;
                        case 'c':
                            exportCsv();
                            break;
                        case 27: // ESC
                            running.set(false);
                            break;
                        default:
                            break;
                    }
                } else {
                    Thread.sleep(40);
                }
            } catch (Exception e) {
                running.set(false);
            }
        }
    }

    // ── CSV export ─────────────────────────────────────────────────────
    private void exportCsv() {
        try {
            String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                    .withZone(ZoneOffset.UTC)
                    .format(Instant.now());
            Path conns = Path.of("sniffnet-connections-" + stamp + ".csv");
            Path hosts = Path.of("sniffnet-hosts-" + stamp + ".csv");
            Report.writeConnections(conns.toString(), tracker.snapshot());
            Report.writeHosts(hosts.toString(), tracker.snapshot());
            statusMessage = "wrote " + conns.getFileName() + " and " + hosts.getFileName();
        } catch (Exception e) {
            statusMessage = "csv export failed: " + e.getMessage();
        }
    }

    // ── render ─────────────────────────────────────────────────────────

    private void render(StringBuilder sb, int cols, int rows) {
        Snapshot snap = tracker.snapshot();
        int y = 0;

        // header bar
        String title = " SNIFFNET (java) | " + deviceLabel
                + " | uptime " + Format.duration(snap.uptimeSeconds());
        line(sb, cols, title, BG_WHITE, FG_BLACK, true);
        y++;

        // protocol totals
        long tcpB = snap.getProtoBytes()[0], udpB = snap.getProtoBytes()[1];
        long icmpB = snap.getProtoBytes()[2], arpB = snap.getProtoBytes()[3], otherB = snap.getProtoBytes()[4];
        long tcpP = snap.getProtoBytes()[0], udpP = snap.getProtoBytes()[1];
        long icmpP = snap.getProtoBytes()[2], arpP = snap.getProtoBytes()[3], otherP = snap.getProtoBytes()[4];
        line(sb, cols,
                String.format(" TCP %s (%d)   UDP %s (%d)   ICMP %s (%d)   ARP %s (%d)   Other %s (%d)",
                        Format.bytes(tcpB), tcpP, Format.bytes(udpB), udpP,
                        Format.bytes(icmpB), icmpP, Format.bytes(arpB), arpP,
                        Format.bytes(otherB), otherP),
                null, null, false);
        y++;

        // rates
        long[] rates = rates(snap.getBuckets());
        line(sb, cols,
                String.format(" rate  \u25bc rx %s   \u25b2 tx %s   pkt/s %s   dropped %d   %s",
                        Format.bitsPerSec(rates[0]), Format.bitsPerSec(rates[1]),
                        Format.pps(rates[2]), snap.getDroppedPackets(),
                        snap.isPaused() ? "[PAUSED]" : statusMessage),
                null, null, false);
        y++;

        // blank separator
        line(sb, cols, "", null, null, false);
        y++;

        // traffic intensity header
        line(sb, cols, "traffic intensity (last " + ConnectionTracker.HISTORY_SECONDS + "s)",
                null, FG_YELLOW, true);
        y++;

        // sparklines
        int chartCols = Math.max(10, cols - 10);
        String rxSpark = sparkline(snap.getBuckets(), chartCols, false);
        String txSpark = sparkline(snap.getBuckets(), chartCols, true);
        line(sb, cols, "  \u25bc rx " + rxSpark, null, FG_GREEN, false);
        y++;
        line(sb, cols, "  \u25b2 tx " + txSpark, null, FG_CYAN, false);
        y++;

        // blank separator
        line(sb, cols, "", null, null, false);
        y++;

        // hosts + connections share remaining space
        int remaining = rows - y - 1; // last row is footer
        if (remaining >= 4) {
            int hostsRows = Math.max(2, remaining * 2 / 5);
            int connsRows = remaining - hostsRows;
            if (connsRows < 2) {
                connsRows = 2;
                hostsRows = remaining - 2;
            }
            y = drawHosts(sb, cols, y, snap, hostsRows);
            y = drawConnections(sb, cols, y, snap, connsRows);
        }

        // footer (always bottom row)
        line(sb, cols,
                " q:quit  p:pause  c:export-csv  |  " + snap.getTotalPackets() + " packets, "
                        + Format.bytes(snap.getTotalBytes()) + " captured",
                BG_WHITE, FG_BLACK, false);
    }

    // ── hosts table ────────────────────────────────────────────────────

    private int drawHosts(StringBuilder sb, int cols, int y, Snapshot snap, int maxRows) {
        line(sb, cols, "TOP HOSTS", null, FG_YELLOW, true);
        y++;
        if (maxRows <= 0) {
            return y;
        }
        line(sb, cols,
                String.format("%-24s %-10s %-4s %4s %12s %12s",
                        "ip", "asn", "cc", "dir", "packets", "bytes"),
                null, FG_WHITE, true);
        y++;
        List<HostStat> hosts = snap.getHosts();
        int n = Math.min(maxRows, hosts.size());
        for (int i = 0; i < n; i++) {
            HostStat h = hosts.get(i);
            String dir = h.txBytes >= h.rxBytes ? "\u25b2" : "\u25bc";
            line(sb, cols,
                    String.format("%-24s %-10s %-4s %4s %12d %12s",
                            h.ip.getHostAddress(),
                            h.asn == null ? "-" : h.asn,
                            h.country == null ? "-" : h.country,
                            dir,
                            h.txPackets + h.rxPackets,
                            Format.bytes(h.totalBytes())),
                    null, null, false);
            y++;
        }
        return y;
    }

    // ── connections table ──────────────────────────────────────────────

    private int drawConnections(StringBuilder sb, int cols, int y, Snapshot snap, int maxRows) {
        line(sb, cols, "TOP CONNECTIONS", null, FG_YELLOW, true);
        y++;
        if (maxRows <= 0) {
            return y;
        }
        int cw = Math.max(6, cols / 3 - 1);
        String fmt = "%-" + cw + "s  %-4s  %-6s  %-13s  %3s %12s %12s";
        line(sb, cols,
                String.format(fmt, "local", "proto", "service", "remote", "dir", "tx", "rx"),
                null, FG_WHITE, true);
        y++;
        List<Connection> conns = snap.getConnections();
        int n = Math.min(maxRows, conns.size());
        for (int i = 0; i < n; i++) {
            Connection c = conns.get(i);
            String local = c.localPort < 0 ? c.localIp.getHostAddress()
                    : c.localIp.getHostAddress() + ":" + c.localPort;
            String remote = c.remotePort < 0 ? c.remoteIp.getHostAddress()
                    : c.remoteIp.getHostAddress() + ":" + c.remotePort;
            line(sb, cols,
                    String.format(fmt,
                            truncate(local, cw),
                            c.protocol.name(),
                            c.service == null ? "-" : truncate(c.service, 13),
                            truncate(remote, cw),
                            c.direction == TrafficDirection.OUTGOING ? "tx" : "rx",
                            Format.bytes(c.txBytes),
                            Format.bytes(c.rxBytes)),
                    null, null, false);
            y++;
        }
        return y;
    }

    // ── helpers ────────────────────────────────────────────────────────

    /** Append one terminal line to the buffer. */
    private static void line(StringBuilder sb, int cols, String text,
                             String bg, String fg, boolean bold) {
        sb.append(RESET);
        if (bg != null) sb.append(bg);
        if (fg != null) sb.append(fg);
        if (bold) sb.append(BOLD);
        sb.append(padRight(truncate(text, cols), cols));
    }

    private static long[] rates(List<SecondBucket> buckets) {
        long rx = 0, tx = 0, pkts = 0;
        int n = buckets.size();
        int start = Math.max(0, n - 3);
        int count = n - start;
        if (count == 0) {
            return new long[]{0, 0, 0};
        }
        for (int i = start; i < n; i++) {
            SecondBucket b = buckets.get(i);
            rx += b.rxBytes;
            tx += b.txBytes;
            pkts += b.rxPackets + b.txPackets;
        }
        return new long[]{rx / count, tx / count, (long) ((double) pkts / count)};
    }

    private static String sparkline(List<SecondBucket> buckets, int width, boolean tx) {
        StringBuilder sb = new StringBuilder(width);
        int n = buckets.size();
        if (n == 0) {
            return " ".repeat(width);
        }
        long max = 0;
        for (SecondBucket b : buckets) {
            max = Math.max(max, tx ? b.txBytes : b.rxBytes);
        }
        int start = Math.max(0, n - width);
        for (int i = start; i < n && sb.length() < width; i++) {
            SecondBucket b = buckets.get(i);
            long v = tx ? b.txBytes : b.rxBytes;
            if (max <= 0 || v <= 0) {
                sb.append(' ');
                continue;
            }
            int level = (int) Math.ceil(v * 8.0 / max);
            sb.append(BLOCKS[Math.max(1, Math.min(8, level)) - 1]);
        }
        while (sb.length() < width) {
            sb.append(' ');
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        if (max <= 1) return s.substring(0, max);
        return s.substring(0, max - 1) + "\u2026";
    }

    private static String padRight(String s, int len) {
        if (s.length() >= len) return s;
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < len) {
            sb.append(' ');
        }
        return sb.toString();
    }
}