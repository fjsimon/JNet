package main.java.com.fjsimon.jn3t.nextrace.tracking;

import main.java.com.fjsimon.jn3t.nextrace.model.Connection;
import main.java.com.fjsimon.jn3t.nextrace.model.HostStat;

public final class ComparatorUtil {
    static java.util.Comparator<Connection> byTotalBytesDesc() {
        return (a, b) -> Long.compare(b.totalBytes(), a.totalBytes());
    }

    static java.util.Comparator<HostStat> byHostTotalBytesDesc() {
        return (a, b) -> Long.compare(b.totalBytes(), a.totalBytes());
    }
}
