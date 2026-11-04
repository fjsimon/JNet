package com.fjsimon.java.network.programming.nextrace;

import java.util.Locale;

/** Human-readable formatting helpers (decimal prefixes). */
public final class Format {

    private static final String[] UNITS = {"B", "KB", "MB", "GB", "TB", "PB"};

    private Format() {}

    /** Format a byte count, e.g. 1536 -> "1.54 KB". */
    public static String bytes(double v) {
        if (v < 1000) {
            return String.format(Locale.ROOT, "%d B", (long) v);
        }
        double val = v;
        int unit = 0;
        while (val >= 1000 && unit < UNITS.length - 1) {
            val /= 1000;
            unit++;
        }
        return String.format(Locale.ROOT, "%.2f %s", val, UNITS[unit]);
    }

    /** Format a byte rate, e.g. 5000 -> "5.00 KB/s". */
    public static String bytesPerSec(double v) {
        return bytes(v) + "/s";
    }

    /** Format a bit rate (bits per second), e.g. 125000 -> "1.00 Mbps". */
    public static String bitsPerSec(double bytesPerSec) {
        return bytes(bytesPerSec * 8) + "ps";
    }

    /** Format a packet rate. */
    public static String pps(double v) {
        return String.format(Locale.ROOT, "%.0f pkt/s", v);
    }

    /** Format a ratio as a percentage. */
    public static String percent(double fraction) {
        return String.format(Locale.ROOT, "%.1f%%", fraction * 100);
    }

    /** Format a duration in seconds as HH:MM:SS. */
    public static String duration(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        return String.format(Locale.ROOT, "%02d:%02d:%02d", h, m, s);
    }
}
