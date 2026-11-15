package main.java.com.fjsimon.jn3t.nextrace;

import java.nio.file.Path;
import java.util.HashSet;

public final class CaptureApplication {

    private final ClientOptions opts;

    public CaptureApplication(ClientOptions opts) {
        this.opts = opts;
    }

    public void execute() throws Exception {

        try (GeoLookup geo = buildGeo(opts);
             CaptureSession session =
                     CaptureEngineFactory.create(opts)) {

            CaptureEngine engine = session.engine();

            ConnectionTracker tracker = new ConnectionTracker(
                    new ServiceRegistry(),
                    geo,
                    new HashSet<>(engine.localAddresses())
            );

            Thread shutdownHook = new Thread(session::close, "shutdown");

            Runtime.getRuntime().addShutdownHook(shutdownHook);

            try (CaptureMonitor monitor = new CaptureMonitor(
                    engine, tracker, session.deviceLabel())) {

                monitor.start();

                session.start(tracker);

                CapturePresenter presenter =
                        CapturePresenterFactory.create(opts);

                presenter.display(
                        opts,
                        engine,
                        tracker,
                        session.deviceLabel()
                );

                if (opts.outputCsv != null && !opts.outputCsv.isBlank()) {
                    writeReports(opts.outputCsv, tracker);
                }

                if (!opts.summary && System.console() != null) {
                    Report.printSummary(
                            tracker.snapshot(),
                            session.deviceLabel()
                    );
                }

            } finally {
                try {
                    Runtime.getRuntime().removeShutdownHook(shutdownHook);
                } catch (IllegalStateException ignored) {
                    // JVM is shutting down.
                }
            }
        }
    }

    private static GeoLookup buildGeo(ClientOptions opts) {
        if (opts.noGeo) {
            return GeoLookup.disabled();
        }
        if (opts.mmdbDir != null) {
            Path dir = Path.of(opts.mmdbDir);
            return GeoLookup.fromFiles(
                    dir.resolve("GeoLite2-ASN.mmdb").toFile(),
                    dir.resolve("GeoLite2-Country.mmdb").toFile());
        }
        return GeoLookup.fromClasspath();
    }

    private static void writeReports(String csvPath, ConnectionTracker tracker) throws Exception {
        String hostPath = csvPath.endsWith(".csv")
                ? csvPath.substring(0, csvPath.length() - 4) + "-hosts.csv"
                : csvPath + "-hosts.csv";
        Report.writeConnections(csvPath, tracker.snapshot());
        Report.writeHosts(hostPath, tracker.snapshot());
        System.out.println("wrote " + csvPath + " and " + hostPath);
    }
}
