package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.ClientOptions;

public final class CaptureViewFactory {

    private CaptureViewFactory() {}

    public static CaptureView create(ClientOptions opts) {

        return opts.summary || System.console() == null
                ? new SummaryView()
                : new TerminalView();
    }
}
