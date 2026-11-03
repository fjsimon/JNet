package com.fjsimon.java.network.programming.nextrace;

public final class ComparatorUtil {
    static java.util.Comparator<Connection> byTotalBytesDesc() {
        return (a, b) -> Long.compare(b.totalBytes(), a.totalBytes());
    }

    static java.util.Comparator<HostStat> byHostTotalBytesDesc() {
        return (a, b) -> Long.compare(b.totalBytes(), a.totalBytes());
    }
}
