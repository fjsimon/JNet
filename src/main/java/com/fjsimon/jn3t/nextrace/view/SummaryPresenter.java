package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.ClientOptions;
import main.java.com.fjsimon.jn3t.nextrace.ConnectionTracker;
import main.java.com.fjsimon.jn3t.nextrace.Format;
import main.java.com.fjsimon.jn3t.nextrace.Report;
import main.java.com.fjsimon.jn3t.nextrace.capture.CaptureEngine;
import main.java.com.fjsimon.jn3t.nextrace.model.Snapshot;

public final class SummaryPresenter implements Presenter {

    @Override
    public void display(
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel) {

        runSummary(engine, tracker, deviceLabel);
    }

    private static void runSummary(
            CaptureEngine engine, ConnectionTracker tracker, String deviceLabel) {
        if (engine.isOffline()) {
            engine.waitForEnd();
            System.out.println();
            Report.printSummary(tracker.snapshot(), deviceLabel);
        } else {
            System.out.println("sniffing on " + deviceLabel
                    + " — press Ctrl-C to stop");
            System.out.println();
            while (!engine.isFinished()) {
                sleepQuietly(2000);
                var snap = tracker.snapshot();
                long[] rates = lastRates(snap);
                System.out.printf(
                        "  %s  packets=%,d  bytes=%s  rx=%s/s  tx=%s/s  dropped=%d%n",
                        java.time.LocalTime.now().withNano(0),
                        snap.getTotalPackets(),
                        Format.bytes(snap.getTotalBytes()),
                        Format.bitsPerSec(rates[0]),
                        Format.bitsPerSec(rates[1]),
                        snap.getDroppedPackets());
                System.out.flush();
            }
            System.out.println();
            Report.printSummary(tracker.snapshot(), deviceLabel);
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static long[] lastRates(Snapshot snapshot) {
        var buckets = snapshot.getBuckets();
        int n = buckets.size();
        int start = Math.max(0, n - 3);
        int count = n - start;
        long rx = 0;
        long tx = 0;
        for (int i = start; i < n; i++) {
            rx += buckets.get(i).rxBytes;
            tx += buckets.get(i).txBytes;
        }
        return new long[]{count == 0 ? 0 : rx / count, count == 0 ? 0 : tx / count};
    }
}
