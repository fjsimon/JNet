package main.java.com.fjsimon.jn3t.nextrace.capture;

import java.io.IOException;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import main.java.com.fjsimon.jn3t.nextrace.model.ParsedPacket;
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
    private static final int ERROR_BACKOFF_MS = 100;

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
    private volatile Thread thread;
    private final CountDownLatch endLatch = new CountDownLatch(1);
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
        endLatch.countDown();
    }

    /** Block until an offline capture reaches EOF or the engine is stopped. */
    public void waitForEnd() {
        if (!offline || thread == null) {
            return;
        }
        try {
            endLatch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Wait up to the given timeout for the capture thread to terminate. */
    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        Thread t = thread;
        if (t == null) {
            return true;
        }
        t.join(unit.toMillis(timeout));
        return !t.isAlive();
    }

    private void captureLoop(PacketConsumer consumer) {
        boolean debug = "true".equals(System.getProperty("sniffnet.debug"));
        CaptureStats stats = new CaptureStats();
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
                    recordCaptureError(e, e.getMessage());
                    continue;
                } catch (Exception e) {
                    recordCaptureError(e, e.getClass().getSimpleName() + ": " + e.getMessage());
                    continue;
                }
                if (pp == null) {
                    if (offline) {
                        break;
                    }
                    onNullPacket(stats, debug);
                    continue;
                }
                processPacket(pp, consumer, stats, debug);
            }
        } finally {
            finishCapture(stats, debug);
        }
    }

    private void recordCaptureError(Exception e, String errorText) {
        lastError = errorText;
        System.err.println("capture error: " + e.getMessage());
        sleepQuietly();
    }

    private void onNullPacket(CaptureStats stats, boolean debug) {
        stats.nullCount++;
        if (debug && stats.nullCount <= 3) {
            System.err.println("[debug] getNextPacket() returned null #" + stats.nullCount);
        }
        updateDropped();
    }

    private void processPacket(
            Packet pp, PacketConsumer consumer, CaptureStats stats, boolean debug) {

        byte[] raw = pp.getRawData();
        ParsedPacket parsed = PacketParser.parse(raw, dlt, toMicros(handle.getTimestamp()));
        if (parsed != null) {
            stats.acceptedCount++;
            stats.byteCount += parsed.lengthBytes;
            consumer.accept(parsed);
            if (debug && stats.acceptedCount <= 5) {
                System.err.println("[debug] packet #" + stats.acceptedCount
                        + " rawLen=" + raw.length
                        + " parsedLen=" + parsed.lengthBytes
                        + " proto=" + parsed.protocol
                        + " src=" + parsed.srcIp
                        + " dst=" + parsed.dstIp
                        + " dlt=" + dlt);
            }
        } else {
            stats.parseFailCount++;
            if (debug && stats.parseFailCount <= 5) {
                StringBuilder hex = new StringBuilder();
                int n = Math.min(40, raw.length);
                for (int i = 0; i < n; i++) hex.append(String.format("%02X", raw[i]));
                System.err.println("[debug] parse returned null #" + stats.parseFailCount
                        + " rawLen=" + raw.length
                        + " dlt=" + dlt
                        + " hex=" + hex);
            }
        }
        if (debug && (stats.acceptedCount + stats.parseFailCount) % 1000 == 0) {
            System.err.println("[debug] stats: accepted=" + stats.acceptedCount
                    + " parseFail=" + stats.parseFailCount + " nullTimeouts=" + stats.nullCount
                    + " bytes=" + stats.byteCount);
        }
        dumpPacket(pp);
    }

    private void dumpPacket(Packet pp) {
        if (dumper == null) {
            return;
        }
        try {
            dumper.dump(pp);
        } catch (Exception e) {
            lastError = e.getMessage();
        }
    }

    private void finishCapture(CaptureStats stats, boolean debug) {
        if (debug) {
            System.err.println("[debug] capture loop exiting: accepted=" + stats.acceptedCount
                    + " parseFail=" + stats.parseFailCount + " nullTimeouts=" + stats.nullCount
                    + " bytes=" + stats.byteCount);
        }
        try {
            updateDropped();
        } catch (Exception ignored) {
            // ignore
        }
        cleanup();
        finished = true;
        running = false;
        endLatch.countDown();
    }

    private static final class CaptureStats {
        long nullCount;
        long parseFailCount;
        long acceptedCount;
        long byteCount;
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

    /** Pause the current thread without throwing on interruption. */
    private static void sleepQuietly() {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ERROR_BACKOFF_MS);
        while (true) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                return;
            }
            LockSupport.parkNanos(remaining);
            if (Thread.interrupted()) {
                Thread.currentThread().interrupt();
                return;
            }
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