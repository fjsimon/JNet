package main.java.com.fjsimon.jn3t.nextrace.view;

import main.java.com.fjsimon.jn3t.nextrace.ClientOptions;

public final class PresenterFactory {

    private PresenterFactory() {}

    public static Presenter create(ClientOptions opts) {

        return opts.summary || System.console() == null
                ? new SummaryPresenter()
                : new TerminalPresenter();
    }
}
