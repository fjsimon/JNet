package com.fjsimon.java.network.programming.nextrace;

import org.apache.commons.lang3.StringUtils;

import java.nio.file.Path;
import java.util.HashSet;

public final class NextraceMain {


    private NextraceMain(){}

    public static void main(String[] args) {

        ClientOptions opts;
        try {
            opts = ClientOptions.parse(args);
        } catch (IllegalArgumentException ex) {
            System.err.println("error: " + ex.getMessage());
            System.err.println();
            System.err.println(ClientOptions.usage());
            System.exit(2);
            return;
        }

        if (opts.help) {
            System.out.print(ClientOptions.usage());
            return;
        }

        if (opts.version) {
            System.out.println("jn3t.nextrace" + ClientOptions.VERSION);
            return;
        }

        if (opts.listAdapters) {
            listAdapters();
            return;
        }

        try {
            run(opts);
        } catch (Exception ex) {
            System.err.println("error: " + ex.getMessage());
            System.exit(1);
        }
    }

    private static void listAdapters() {
        try {
            var adapters = CaptureEngine.listAdapters();
            System.out.println("available network adapters:");
            if (adapters.isEmpty()) {
                System.out.println("  (none found)");
            }
            for (var a : adapters) {
                System.out.printf("  %-18s %s  [%s]%n",
                        a.name, a.description, a.displayAddresses());
            }
        } catch (Exception e) {
            System.err.println("could not list adapters: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void run(ClientOptions opts) throws Exception {

        ServiceRegistry registry = new ServiceRegistry();
        GeoLookup geo = buildGeo(opts);

        CaptureEngine engine;
        String deviceName;
        if (StringUtils.isNotEmpty(opts.readFile)) {
            engine = CaptureEngine.openOffline(opts.readFile, opts.filter, opts.writeFile);
            deviceName = opts.readFile;
        } else {
            deviceName = StringUtils.isNotBlank(opts.adapter) ? opts.adapter :  pickDefaultAdapter();
            checkPermissions(deviceName);
            engine = CaptureEngine.openLive(deviceName, opts.filter, opts.writeFile);
        }

        String deviceLabel = (StringUtils.isNotEmpty(opts.readFile) ? "file " : "iface ")
            + deviceName + " [" + engine.linkTypeName() + "]";

        ConnectionTracker tracker = new ConnectionTracker(registry, geo, new HashSet<>(engine.localAddresses()));

        Thread stats = new Thread(() -> {

            while (true ) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    return;
                }
                tracker.setDroppedPackets(engine.droppedPackets());
            }
        }, "stats-poll");
        stats.setDaemon(true);
        stats.start();

        final CaptureEngine engineRef = engine;
        Runtime.getRuntime().addShutdownHook(new Thread(engineRef::stop, "shutdown"));

        engine.start(tracker::process);

        Thread diag = new Thread(() -> {
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                return;
            }
            if (engine.isRunning() && tracker.snapshot().getTotalPackets() == 0) {
                System.err.println();
                System.err.println("WARNING: no packets captured after 5 seconds.");
                System.err.println("  Possible causes:");
                System.err.println("    - not running as root (need CAP_NET_RAW)");
                System.err.println("    - no traffic on " + deviceLabel);
                System.err.println("    - pcap4j incompatibility with JVM " + System.getProperty("java.version"));
                System.err.println("  Try: sudo java -jar jn3t.jar -a " + deviceLabel.split(" ")[1]);
                System.err.println();
            }
        }, "capture-diag");
        diag.setDaemon(true);
        diag.start();



        engine.stop();
        geo.shutdown();
    }

    private static void checkPermissions(String deviceName) {

        String os = System.getProperty("os.name", "").toLowerCase();
        if(!os.contains("Linux")) {
            return;
        }
        try {
            Process p = new ProcessBuilder("whoami").redirectErrorStream(true).start();
            String user;
            try (var in = p.getInputStream()) {
                user = new String(in.readAllBytes()).trim();
            }
            p.waitFor();
            if("root".equals(user)) {
                return;
            }
        } catch (Exception ex) {
            return;
        }

        try{
            Process p = new ProcessBuilder("id", "-n", "-G").redirectErrorStream(true).start();
            String groups;
            try (var in = p.getInputStream()) {
                groups = new String(in.readAllBytes()).trim();
            }
            p.waitFor();
            if (groups.contains(" wheel ") || groups.contains(" pcap ")) {
                return;
            }
        } catch(Exception ex) {}

        System.err.println("WARNING: running as non-root user -- live capture requires root or CAP_NET_RAW.");
        System.err.println("  Run with: sudo java -jar jn3t.jar");
        System.err.println("  Or set capability: sudo setcap cap_net_raw+ep $(which java)");
        System.err.println();

    }

    private static String pickDefaultAdapter() throws Exception {

        var adapters = CaptureEngine.listAdapters();
        if(adapters.isEmpty()) {
            throw new IllegalStateException("no network adapters found");
        }
        for (var a : adapters) {
            if(!a.isLoopback()) {
                return a.name;
            }
        }
        return adapters.getFirst().name;
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
}
