package main.java.com.fjsimon.jn3t.nextrace.capture;

import main.java.com.fjsimon.jn3t.nextrace.ConnectionTracker;

public final class CaptureSession implements AutoCloseable {

    private final CaptureEngine engine;
    private final String deviceName;
    private final String deviceLabel;

    public CaptureSession(
            CaptureEngine engine,
            String deviceName,
            String deviceLabel) {

        this.engine = engine;
        this.deviceName = deviceName;
        this.deviceLabel = deviceLabel;
    }

    public CaptureEngine engine() {
        return engine;
    }

    public String deviceName() {
        return deviceName;
    }

    public String deviceLabel() {
        return deviceLabel;
    }

    public void start(ConnectionTracker tracker) throws Exception {
        engine.start(tracker::process);
    }

    @Override
    public void close() {
        engine.stop();
    }
}