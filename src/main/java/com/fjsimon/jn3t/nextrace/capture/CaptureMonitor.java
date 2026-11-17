package main.java.com.fjsimon.jn3t.nextrace.capture;

import main.java.com.fjsimon.jn3t.nextrace.ConnectionTracker;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class CaptureMonitor implements AutoCloseable {

    private final CaptureEngine engine;
    private final ConnectionTracker tracker;
    private final String deviceLabel;

    private final ScheduledExecutorService scheduler =
            Executors.newScheduledThreadPool(2);

    public CaptureMonitor(
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel) {

        this.engine = engine;
        this.tracker = tracker;
        this.deviceLabel = deviceLabel;
    }

    public void start() {

        scheduler.scheduleWithFixedDelay(
                () -> tracker.setDroppedPackets(engine.droppedPackets()),
                1, 1, TimeUnit.SECONDS
        );

        scheduler.schedule(this::diagnose, 5, TimeUnit.SECONDS);
    }

    private void diagnose() {

        if (engine.isRunning()
                && tracker.snapshot().getTotalPackets() == 0) {

            System.err.println();
            System.err.println(
                    "WARNING: no packets captured after 5 seconds."
            );
            System.err.println("  Possible causes:");
            System.err.println("    - not running as root (need CAP_NET_RAW)");
            System.err.println("    - no traffic on " + deviceLabel);
            System.err.println(
                    "    - pcap4j incompatibility with JVM "
                            + System.getProperty("java.version")
            );
            System.err.println();
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }
}
