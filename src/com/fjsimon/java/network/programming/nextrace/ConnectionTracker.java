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

    public synchronized Snapshot snapshot() {
        return Snapshot.builder()
                .totalPackets(totalPackets)
                .totalBytes(totalBytes)
                .droppedPackets(droppedPackets)
                .firstSeenMicros(firstSeenMicros)
                .lastSeenMicros(lastSeenMicros)
                .paused(paused)
                .protoBytes(protoBytes.clone())
                .protoPackets(protoPackets.clone())
                .connections(connections.values().stream()
                        .sorted(ComparatorUtil.byTotalBytesDesc())
                        .collect(Collectors.toCollection(ArrayList::new)))
                .hosts(hosts.values().stream()
                        .sorted(ComparatorUtil.byHostTotalBytesDesc())
                        .collect(Collectors.toCollection(ArrayList::new)))
                .buckets(new ArrayList<>(buckets.values()))
                .build();
    }

    /**
     * Immutable view of the tracker state for rendering.
     */
    public static final class Snapshot {

        private final long totalPackets;
        private final long totalBytes;
        private final long droppedPackets;
        private final long firstSeenMicros;
        private final long lastSeenMicros;
        private final boolean paused;

        private final long[] protoBytes;
        private final long[] protoPackets;

        private final List<Connection> connections;
        private final List<HostStat> hosts;
        private final List<SecondBucket> buckets;

        private Snapshot(Builder builder) {
            this.totalPackets = builder.totalPackets;
            this.totalBytes = builder.totalBytes;
            this.droppedPackets = builder.droppedPackets;
            this.firstSeenMicros = builder.firstSeenMicros;
            this.lastSeenMicros = builder.lastSeenMicros;
            this.paused = builder.paused;

            this.protoBytes = builder.protoBytes.clone();
            this.protoPackets = builder.protoPackets.clone();

            this.connections = List.copyOf(builder.connections);
            this.hosts = List.copyOf(builder.hosts);
            this.buckets = List.copyOf(builder.buckets);
        }

        public static Builder builder() {
            return new Builder();
        }

        // Getters

        public long getTotalPackets() {
            return totalPackets;
        }

        public long getTotalBytes() {
            return totalBytes;
        }

        public long getDroppedPackets() {
            return droppedPackets;
        }

        public long getFirstSeenMicros() {
            return firstSeenMicros;
        }

        public long getLastSeenMicros() {
            return lastSeenMicros;
        }

        public boolean isPaused() {
            return paused;
        }

        public long[] getProtoBytes() {
            return protoBytes.clone();
        }

        public long[] getProtoPackets() {
            return protoPackets.clone();
        }

        public List<Connection> getConnections() {
            return connections;
        }

        public List<HostStat> getHosts() {
            return hosts;
        }

        public List<SecondBucket> getBuckets() {
            return buckets;
        }

        public long uptimeSeconds() {
            if (firstSeenMicros < 0) {
                return 0;
            }

            return Math.max(
                    0,
                    (lastSeenMicros - firstSeenMicros) / 1_000_000L
            );
        }

        // Builder

        public static final class Builder {

            private long totalPackets;
            private long totalBytes;
            private long droppedPackets;
            private long firstSeenMicros = -1;
            private long lastSeenMicros;
            private boolean paused;

            private long[] protoBytes = new long[0];
            private long[] protoPackets = new long[0];

            private List<Connection> connections = List.of();
            private List<HostStat> hosts = List.of();
            private List<SecondBucket> buckets = List.of();

            private Builder() {
            }

            public Builder totalPackets(long value) {
                this.totalPackets = value;
                return this;
            }

            public Builder totalBytes(long value) {
                this.totalBytes = value;
                return this;
            }

            public Builder droppedPackets(long value) {
                this.droppedPackets = value;
                return this;
            }

            public Builder firstSeenMicros(long value) {
                this.firstSeenMicros = value;
                return this;
            }

            public Builder lastSeenMicros(long value) {
                this.lastSeenMicros = value;
                return this;
            }

            public Builder paused(boolean value) {
                this.paused = value;
                return this;
            }

            public Builder protoBytes(long[] value) {
                this.protoBytes = value.clone();
                return this;
            }

            public Builder protoPackets(long[] value) {
                this.protoPackets = value.clone();
                return this;
            }

            public Builder connections(List<Connection> value) {
                this.connections = List.copyOf(value);
                return this;
            }

            public Builder hosts(List<HostStat> value) {
                this.hosts = List.copyOf(value);
                return this;
            }

            public Builder buckets(List<SecondBucket> value) {
                this.buckets = List.copyOf(value);
                return this;
            }

            public Snapshot build() {
                return new Snapshot(this);
            }
        }
    }

    private static final class ComparatorUtil {
        static java.util.Comparator<Connection> byTotalBytesDesc() {
            return (a, b) -> Long.compare(b.totalBytes(), a.totalBytes());
        }

        static java.util.Comparator<HostStat> byHostTotalBytesDesc() {
            return (a, b) -> Long.compare(b.totalBytes(), a.totalBytes());
        }
    }
}
