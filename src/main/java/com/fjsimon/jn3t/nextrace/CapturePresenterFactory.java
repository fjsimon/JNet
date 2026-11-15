package main.java.com.fjsimon.jn3t.nextrace;

public final class CapturePresenterFactory {

    private CapturePresenterFactory() {}

    public static CapturePresenter create(ClientOptions opts) {

        return opts.summary || System.console() == null
                ? new SummaryPresenter()
                : new TerminalPresenter();
    }
}
