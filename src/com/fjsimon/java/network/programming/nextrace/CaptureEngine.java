package com.fjsimon.java.network.programming.nextrace;

import java.io.IOException;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

/**
 * Capture engine built on top of pcap4j. Supports live sniffing on a network
 * adapter, offline reading of pcap/pcapng files, BPF filtering and PCAP export.
 */
public final class CaptureEngine {

    public static final int SNAP_LEN = 65535;
    private static final int LIVE_TIMEOUT_MS = 200;

    /** Consumer invoked for every parsed packet. */
    public interface PacketConsumer {
        void accept(ParsedPacket packet);
    }

    private final PcapHandle handle;
    private final PcapDumper dumper;
    private final int dlt;
    private final boolean offline;
    private final List<InetAddress> localAddresses = new ArrayList<>();

    private volatile boolean running;
    private volatile boolean finished;
    private Thread thread;
    private String lastError;

    private CaptureEngine(
            PcapHandle handle,
            PcapDumper dumper,
            boolean offline,
            List<InetAddress> localAddresses) {
        this.handle = handle;
        this.dumper = dumper;
        this.offline = offline;
        this.dlt = handle.getDlt().value();
        if ("true".equals(System.getProperty("sniffnet.debug"))) {
            System.err.println("[debug] CaptureEngine: dlt=" + this.dlt
                    + " dltObj=" + handle.getDlt()
                    + " localAddrs=" + localAddresses);
        }
        if (localAddresses != null) {
            this.localAddresses.addAll(localAddresses);
        }
    }

    /** List all network adapters visible to libpcap. */
    public static List<AdapterInfo> listAdapters() throws PcapNativeException {
        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        List<AdapterInfo> result = new ArrayList<>();
        for (PcapNetworkInterface nif : nifs) {
            List<InetAddress> addrs = new ArrayList<>();
            for (PcapAddress a : nif.getAddresses()) {
                if (a.getAddress() != null) {
                    addrs.add(a.getAddress());
                }
            }
            result.add(new AdapterInfo(nif.getName(), nif.getDescription(), addrs));
        }
        return result;
    }

    /** Open a live capture on the given adapter. */
    public static CaptureEngine openLive(
            String deviceName, String filter, String dumpPath)
            throws PcapNativeException, IOException {
        PcapNetworkInterface nif = Pcaps.getDevByName(deviceName);
        if (nif == null) {
            throw new PcapNativeException("no such adapter: " + deviceName);
        }
        PcapHandle handle = nif.openLive(SNAP_LEN, PromiscuousMode.PROMISCUOUS, LIVE_TIMEOUT_MS);
        List<InetAddress> addrs = new ArrayList<>();
        for (PcapAddress a : nif.getAddresses()) {
            if (a.getAddress() != null) {
                addrs.add(a.getAddress());
            }
        }
        return open(handle, filter, dumpPath, false, addrs);
    }

    /** Open an offline capture from a pcap/pcapng file. */
    public static CaptureEngine openOffline(String file, String filter, String dumpPath)
            throws PcapNativeException, IOException {
        PcapHandle handle = Pcaps.openOffline(file);
        return open(handle, filter, dumpPath, true, Collections.emptyList());
    }

    private static CaptureEngine open(
            PcapHandle handle, String filter, String dumpPath, boolean offline,
            List<InetAddress> localAddresses)
            throws PcapNativeException, IOException {
        PcapDumper dumper = null;
        try {
            if (filter != null && !filter.isBlank()) {
                handle.setFilter(
                        filter,
                        BpfProgram.BpfCompileMode.OPTIMIZE,
                        null);
            }
            if (dumpPath != null) {
                dumper = handle.dumpOpen(dumpPath);
            }
        } catch (Exception e) {
            handle.close();
            if (dumper != null) {
                dumper.close();
            }
            if (e instanceof PcapNativeException pe) throw pe;
            if (e instanceof IOException ioe) throw ioe;
            throw new IOException(e);
        }
        return new CaptureEngine(handle, dumper, offline, localAddresses);
    }

    public List<InetAddress> localAddresses() {
        return localAddresses;
    }

    public String linkTypeName() {
        return handle.getDlt().name();
    }

    public boolean isOffline() {
        return offline;
    }

    public boolean isRunning() {
        return running;
    }

    public boolean isFinished() {
        return finished;
    }

    public String lastError() {
        return lastError;
    }

    /** Start the capture thread feeding parsed packets to the consumer. */
    public void start(PacketConsumer consumer) {
        running = true;
        thread = new Thread(() -> captureLoop(consumer), "capture");
        thread.setDaemon(false);
        thread.start();
    }

    /** Ask the capture thread to stop as soon as possible. */
    public void stop() {
        running = false;
    }

    /** Block until an offline capture reaches EOF. */
    public void waitForEnd() {
        if (!offline) {
            return;
        }
        while (!finished && running) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void captureLoop(PacketConsumer consumer) {
        boolean debug = "true".equals(System.getProperty("sniffnet.debug"));
        long nullCount = 0;
        long parseFailCount = 0;
        long acceptedCount = 0;
        long byteCount = 0;
        if (debug) {
            System.err.println("[debug] capture loop starting, dlt=" + dlt + " handle.isOpen=" + handle.isOpen());
        }
        try {
            while (running) {
                Packet pp;
                try {
                    pp = handle.getNextPacket();
                } catch (org.pcap4j.core.NotOpenException e) {
                    if (offline) {
                        break;
                    }
                    lastError = e.getMessage();
                    System.err.println("capture error: " + e.getMessage());
                    sleepQuietly(100);
                    continue;
                } catch (Exception e) {
                    lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
                    System.err.println("capture error: " + e.getMessage());
                    sleepQuietly(100);
                    continue;
                }
                if (pp == null) {
                    if (offline) {
                        break;
                    }
                    nullCount++;
                    if (debug && nullCount <= 3) {
                        System.err.println("[debug] getNextPacket() returned null #" + nullCount);
                    }
                    updateDropped();
                    continue;
                }
                byte[] raw = pp.getRawData();
                ParsedPacket parsed = PacketParser.parse(
                        raw, dlt, toMicros(handle.getTimestamp()));
                if (parsed != null) {
                    acceptedCount++;
                    byteCount += parsed.lengthBytes;
                    consumer.accept(parsed);
                    if (debug && acceptedCount <= 5) {
                        System.err.println("[debug] packet #" + acceptedCount
                                + " rawLen=" + raw.length
                                + " parsedLen=" + parsed.lengthBytes
                                + " proto=" + parsed.protocol
                                + " src=" + parsed.srcIp
                                + " dst=" + parsed.dstIp
                                + " dlt=" + dlt);
                    }
                } else {
                    parseFailCount++;
                    if (debug && parseFailCount <= 5) {
                        StringBuilder hex = new StringBuilder();
                        int n = Math.min(40, raw.length);
                        for (int i = 0; i < n; i++) hex.append(String.format("%02X", raw[i]));
                        System.err.println("[debug] parse returned null #" + parseFailCount
                                + " rawLen=" + raw.length
                                + " dlt=" + dlt
                                + " hex=" + hex);
                    }
                }
                if (debug && (acceptedCount + parseFailCount) % 1000 == 0) {
                    System.err.println("[debug] stats: accepted=" + acceptedCount
                            + " parseFail=" + parseFailCount + " nullTimeouts=" + nullCount
                            + " bytes=" + byteCount);
                }
                if (dumper != null) {
                    try {
                        dumper.dump(pp);
                    } catch (Exception e) {
                        lastError = e.getMessage();
                    }
                }
            }
        } finally {
            if (debug) {
                System.err.println("[debug] capture loop exiting: accepted=" + acceptedCount
                        + " parseFail=" + parseFailCount + " nullTimeouts=" + nullCount
                        + " bytes=" + byteCount);
            }
            try {
                updateDropped();
            } catch (Exception ignored) {
                // ignore
            }
            cleanup();
            finished = true;
            running = false;
        }
    }

    private void updateDropped() {
        try {
            if (handle.isOpen()) {
                PcapStat stat = handle.getStats();
                if (stat != null) {
                    dropped = stat.getNumPacketsDropped();
                }
            }
        } catch (Exception ignored) {
            // stats are best-effort
        }
    }

    private volatile long dropped;

    public long droppedPackets() {
        return dropped;
    }

    private static long toMicros(Timestamp ts) {
        if (ts == null) {
            return System.currentTimeMillis() * 1000L;
        }
        return ts.getTime() * 1000L + (ts.getNanos() % 1_000_000L) / 1000L;
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void cleanup() {
        if (dumper != null) {
            try {
                dumper.close();
            } catch (Exception ignored) {
                // ignore
            }
        }
        if (handle.isOpen()) {
            handle.close();
        }
    }
}