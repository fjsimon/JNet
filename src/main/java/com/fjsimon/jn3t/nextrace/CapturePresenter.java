package main.java.com.fjsimon.jn3t.nextrace;

public interface CapturePresenter {

    void display(
            ClientOptions opts,
            CaptureEngine engine,
            ConnectionTracker tracker,
            String deviceLabel
    );
}