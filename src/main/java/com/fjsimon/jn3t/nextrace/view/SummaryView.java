package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.tracking.ConnectionTracker;
import main.java.com.fjsimon.jn3t.nextrace.Format;
import main.java.com.fjsimon.jn3t.nextrace.Report;
import main.java.com.fjsimon.jn3t.nextrace.capture.CaptureEngine;
import main.java.com.fjsimon.jn3t.nextrace.model.Snapshot;

import java.util.concurrent.TimeUnit;

public final class SummaryView implements CaptureView {

    private static final long STATUS_INTERVAL_MS = 2000;

    @Override
    public void render(
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel) {

        runSummary(engine, tracker, deviceLabel);
    }

    private static void runSummary(
            CaptureEngine engine, ConnectionTracker tracker, String deviceLabel) {

        if (engine.isOffline()) {
            engine.waitForEnd();
        } else {
            runLiveSummary(engine, tracker, deviceLabel);
        }
        printFinalSummary(tracker, deviceLabel);
    }

    private static void runLiveSummary(
            CaptureEngine engine, ConnectionTracker tracker, String deviceLabel) {

        System.out.println("sniffing on " + deviceLabel
                + " — press Ctrl-C to stop");
        System.out.println();

        try {
            while (!engine.isFinished()) {
                if (engine.awaitTermination(STATUS_INTERVAL_MS, TimeUnit.MILLISECONDS)) {
                    break;
                }
                printStatus(tracker.snapshot());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void printFinalSummary(ConnectionTracker tracker, String deviceLabel) {
        System.out.println();
        Report.printSummary(tracker.snapshot(), deviceLabel);
    }

    private static void printStatus(Snapshot snap) {
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
