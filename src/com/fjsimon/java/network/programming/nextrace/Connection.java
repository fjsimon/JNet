package com.fjsimon.java.network.programming.nextrace;

import java.net.InetAddress;

/** Aggregated statistics for a single network connection (both directions). */
public final class Connection {
    public final ConnectionKey key;
    public final InetAddress localIp;
    public final int localPort;
    public final InetAddress remoteIp;
    public final int remotePort;
    public final Protocol protocol;
    /** Direction of the majority/first observed traffic. */
    public final TrafficDirection direction;
    /** Identified upper-layer service (or null). */
    public final String service;

    public long txBytes;
    public long rxBytes;
    public long txPackets;
    public long rxPackets;
    public long firstTimestampMicros;
    public long lastTimestampMicros;

    Connection(ConnectionKey key, TrafficDirection direction, String service) {
        this.key = key;
        this.localIp = key.localIp();
        this.localPort = key.localPort();
        this.remoteIp = key.remoteIp();
        this.remotePort = key.remotePort();
        this.protocol = key.protocol();
        this.direction = direction;
        this.service = service;
    }

    public long totalBytes() {
        return txBytes + rxBytes;
    }

    public long totalPackets() {
        return txPackets + rxPackets;
    }
}

