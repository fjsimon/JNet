package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.ConnectionTracker;
import main.java.com.fjsimon.jn3t.nextrace.capture.CaptureEngine;

public final class TerminalView implements CaptureView {

    @Override
    public void render(
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel) {

        new Terminal(tracker, deviceLabel).run();
    }
}