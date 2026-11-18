package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.ClientOptions;
import main.java.com.fjsimon.jn3t.nextrace.ConnectionTracker;
import main.java.com.fjsimon.jn3t.nextrace.capture.CaptureEngine;

public final class TerminalPresenter implements Presenter {

    @Override
    public void display(
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel) {

        new Terminal(tracker, deviceLabel).run();
    }
}