package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.ClientOptions;
import main.java.com.fjsimon.jn3t.nextrace.ConnectionTracker;
import main.java.com.fjsimon.jn3t.nextrace.capture.CaptureEngine;

public interface Presenter {

    void display(
            ClientOptions opts,
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel
    );
}