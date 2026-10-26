package com.fjsimon.java.network.programming.nextrace;

import java.net.InetAddress;

/** Aggregated statistics for a single host, enriched asynchronously with geo data. */
public final class HostStat {
    public final InetAddress ip;

    public long txBytes;
    public long rxBytes;
    public long txPackets;
    public long rxPackets;
    public long firstSeenMicros;
    public long lastSeenMicros;
    public boolean local;

    /** Filled asynchronously by the geo enricher. */
    public volatile String asn;
    public volatile String org;
    public volatile String country;

    public HostStat(InetAddress ip) {
        this.ip = ip;
    }

    public long totalBytes() {
        return txBytes + rxBytes;
    }
}

