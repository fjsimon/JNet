package com.fjsimon.java.network.programming.nextrace;

import com.fjsimon.java.network.programming.nextrace.ParsedPacket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Core aggregation engine: turns parsed packets into per-connection, per-host and
 * per-second statistics. Mirrors sniffnet's manage_packets / InfoTraffic logic.
 */
public final class ConnectionTracker {

    /** Number of per-second buckets kept for the intensity chart. */
    public static final int HISTORY_SECONDS = 120;

    private final Map<ConnectionKey, Connection> connections = new HashMap<>();
    private final Map<InetAddress, HostStat> hosts = new HashMap<>();
    private final ServiceRegistry serviceRegistry;
    private final HostEnricher hostEnricher;

    /** Addresses of the interface being sniffed (empty when reading a file). */
    private final Set<InetAddress> localAddrs;

    private final TreeMap<Long, SecondBucket> buckets = new TreeMap<>();
    private long currentBucketSecond = Long.MIN_VALUE;
    private SecondBucket currentBucket;

    private final long[] protoBytes = new long[Protocol.values().length];
    private final long[] protoPackets = new long[Protocol.values().length];

    private long totalPackets;
    private long totalBytes;
    private long droppedPackets;
    private long firstSeenMicros = -1;
    private long lastSeenMicros = -1;
    private boolean paused;

    public ConnectionTracker(
            ServiceRegistry serviceRegistry,
            HostEnricher hostEnricher,
            Set<InetAddress> localAddrs) {

        this.serviceRegistry = serviceRegistry;
        this.hostEnricher = hostEnricher;
        this.localAddrs = localAddrs == null ? Set.of() : localAddrs;
    }

    public synchronized void process(ParsedPacket p) {
        if(paused) {
            return;
        }

        long ts = p.timestampMicros;
        if(firstSeenMicros < 0) {
            firstSeenMicros = ts;
        }
        lastSeenMicros = Math.max(lastSeenMicros, ts);

        totalPackets++;
        totalBytes += p.lengthBytes;

        int pIdx = p.protocol == null ? Protocol.OTHER.ordinal() : p.protocol.ordinal();
        protoPackets[pIdx]++;
        protoBytes[pIdx] += p.lengthBytes;

        updateBucket(ts / 1_000_000L, p);

        InetAddress src = p.srcIp;
        InetAddress dst = p.dstIp;
        if (src == null || dst == null || p.protocol == null || !p.protocol.isTrackedForConnections()) {
            return;
        }

        boolean srcLocal = isLocal(src);
        boolean dstLocal = isLocal(dst);

        TrafficDirection dir;
        if (src.isLoopbackAddress() && dst.isLoopbackAddress() && p.srcPort >= 0 && p.dstPort >= 0) {
            // loopback: pick direction from port ordering, as sniffnet does
            dir = p.srcPort > p.dstPort ? TrafficDirection.OUTGOING : TrafficDirection.INCOMING;
        } else if (srcLocal) {
            dir = TrafficDirection.OUTGOING;
        } else {
            dir = TrafficDirection.INCOMING;
        }

        InetAddress localIp = srcLocal ? src : dst;
        InetAddress remoteIp = srcLocal ? dst : src;
        int localPort = srcLocal ? p.srcPort : p.dstPort;
        int remotePort = srcLocal ? p.dstPort : p.srcPort;

        ConnectionKey key = new ConnectionKey(localIp, localPort, remoteIp, remotePort, p.protocol);
        Connection conn = connections.get(key);
        if (conn == null) {
            String service = determineService(p.protocol, p.srcPort, p.dstPort, dst, dir);
            conn = new Connection(key, dir, service);
            connections.put(key, conn);
            conn.firstTimestampMicros = ts;
        }
        conn.lastTimestampMicros = ts;


        if (dir == TrafficDirection.OUTGOING) {
            conn.txBytes += p.lengthBytes;
            conn.txPackets++;
        } else {
            conn.rxBytes += p.lengthBytes;
            conn.rxPackets++;
        }

        // host stats (remote host is the interesting one)
        updateHost(remoteIp, localIp, dir, p.lengthBytes, ts);
    }
}
