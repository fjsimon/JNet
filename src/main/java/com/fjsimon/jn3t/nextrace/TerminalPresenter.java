package main.java.com.fjsimon.jn3t.nextrace;

public final class TerminalPresenter implements CapturePresenter {

    @Override
    public void display(
            ClientOptions opts,
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel) {

        new Terminal(tracker, deviceLabel).run();
    }
}