package com.fjsimon.java.network.programming.nextrace;

/** Per-second traffic bucket used for the real-time intensity chart. */
public final class SecondBucket {
    public final long second;
    public long txBytes;
    public long rxBytes;
    public long txPackets;
    public long rxPackets;

    public SecondBucket(long second) {
        this.second = second;
    }
}

