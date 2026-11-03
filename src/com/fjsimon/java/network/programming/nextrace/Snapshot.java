package com.fjsimon.java.network.programming.nextrace;

import java.util.List;

/**
 * Immutable view of the connection tracker state for rendering.
 */
public final class Snapshot {

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
