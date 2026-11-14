package main.java.com.fjsimon.jn3t.nextrace;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

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

    private void updateBucket(long second, ParsedPacket p) {

        if (currentBucketSecond == Long.MIN_VALUE) {
            SecondBucket b = new SecondBucket(second);
            buckets.put(second, b);
            currentBucket = b;
            currentBucketSecond = second;
        } else if (second > currentBucketSecond) {
            // fill gaps if any (e.g. offline captures with sparse timestamps)
            long gap = second - currentBucketSecond;
            if (gap <= HISTORY_SECONDS + 1) {
                for (long s = currentBucketSecond + 1; s <= second; s++) {
                    SecondBucket b = new SecondBucket(s);
                    buckets.put(s, b);
                    currentBucket = b;
                    currentBucketSecond = s;
                }
            } else {
                // large jump: discard old buckets, start fresh
                buckets.clear();
                SecondBucket b = new SecondBucket(second);
                buckets.put(second, b);
                currentBucket = b;
                currentBucketSecond = second;
            }
            while (buckets.size() > HISTORY_SECONDS) {
                long oldest = buckets.firstKey();
                buckets.remove(oldest);
            }
        }
        if (second == currentBucketSecond && currentBucket != null) {
            if (isTx(p)) {
                currentBucket.txBytes += p.lengthBytes;
                currentBucket.txPackets++;
            } else {
                currentBucket.rxBytes += p.lengthBytes;
                currentBucket.rxPackets++;
            }
        }
    }

    private boolean isTx(ParsedPacket p) {

        if (p.srcIp == null) {
            return false;
        }
        return isLocal(p.srcIp);
    }

    private boolean isLocal(InetAddress ip) {

        if (!localAddrs.isEmpty()) {
            return localAddrs.contains(ip) || ip.isLoopbackAddress();
        }
        // heuristic for offline files: private/reserved addresses count as local
        if (ip.isLoopbackAddress() || ip.isLinkLocalAddress() || ip.isSiteLocalAddress()) {
            return true;
        }
        if (ip.isAnyLocalAddress()) {
            return false;
        }
        byte[] a = ip.getAddress();
        if (a.length == 4) {
            int first = a[0] & 0xFF;
            // 10/8, 172.16/12, 192.168/16
            if (first == 10) return true;
            if (first == 172 && (a[1] & 0xFF) >= 16 && (a[1] & 0xFF) <= 31) return true;
            if (first == 192 && (a[1] & 0xFF) == 168) return true;
        } else {
            // fc00::/7
            if ((a[0] & 0xFE) == 0xFC) return true;
        }
        return false;
    }

    private String determineService(
            Protocol proto, int sport, int dport, InetAddress dstIp, TrafficDirection dir) {

        if (proto != Protocol.TCP && proto != Protocol.UDP) {
            return null;
        }
        String s1 = serviceRegistry.lookup(proto, sport);
        String s2 = serviceRegistry.lookup(proto, dport);
        boolean bonusDir =
                dir == TrafficDirection.OUTGOING
                        || isMulticastAddr(dstIp)
                        || isBroadcastAddress(dstIp);
        int score1 = serviceScore(s1, sport, !bonusDir);
        int score2 = serviceScore(s2, dport, bonusDir);
        return score1 > score2 ? s1 : s2;
    }

    private static boolean isBroadcastAddress(InetAddress ip) {

        byte[] a = ip.getAddress();
        if (a.length != 4) {
            return false;
        }
        for (byte b : a) {
            if (b != (byte) 0xFF) {
                return false;
            }
        }
        return true;
    }

    private static boolean isMulticastAddr(InetAddress ip) {

        byte[] a = ip.getAddress();
        if (a.length == 4) {
            // IPv4 multicast: 224.0.0.0/4
            int first = a[0] & 0xFF;
            return first >= 224 && first <= 239;
        } else if (a.length == 16) {
            // IPv6 multicast: ff00::/8
            return (a[0] & 0xFF) == 0xFF;
        }
        return false;
    }

    private static int serviceScore(String service, int port, boolean bonusDirection) {

        int serviceIsSome = service != null ? 1 : 0;
        int portIsWellKnown = port >= 0 && port < 1024 ? 3 : 1;
        int bonus = bonusDirection ? 1 : 0;
        return serviceIsSome * (portIsWellKnown + bonus);
    }

    private void updateHost(InetAddress remote, InetAddress local, TrafficDirection dir, long bytes, long ts) {

        HostStat h = hosts.get(remote);
        boolean created = false;
        if (h == null) {
            h = new HostStat(remote);
            hosts.put(remote, h);
            h.local = localAddrs.contains(remote) || remote.isLoopbackAddress();
            h.firstSeenMicros = ts;
            created = true;
        }
        if (dir == TrafficDirection.OUTGOING) {
            h.txBytes += bytes;
            h.txPackets++;
        } else {
            h.rxBytes += bytes;
            h.rxPackets++;
        }
        h.lastSeenMicros = ts;
        if (created && hostEnricher != null) {
            hostEnricher.enrich(h);
        }
    }

    public synchronized void setDroppedPackets(long dropped) {

        this.droppedPackets = dropped;
    }

    public synchronized void setPaused(boolean paused) {

        this.paused = paused;
    }

    public synchronized boolean isPaused() {

        return paused;
    }

    public ServiceRegistry serviceRegistry() {

        return serviceRegistry;
    }

    public HostStat hostStat(InetAddress ip) {

        return hosts.get(ip);
    }

    public synchronized Snapshot snapshot() {
        return Snapshot.builder()
                .totalPackets(totalPackets)
                .totalBytes(totalBytes)
                .droppedPackets(droppedPackets)
                .firstSeenMicros(firstSeenMicros)
                .lastSeenMicros(lastSeenMicros)
                .paused(paused)
                .protoBytes(protoBytes)
                .protoPackets(protoPackets)
                .connections(connections.values().stream()
                        .sorted(ComparatorUtil.byTotalBytesDesc())
                        .toList())
                .hosts(hosts.values().stream()
                        .sorted(ComparatorUtil.byHostTotalBytesDesc())
                        .toList())
                .buckets(new ArrayList<>(buckets.values()))
                .build();
    }
}
