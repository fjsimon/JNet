package main.java.com.fjsimon.jn3t.nextrace;

import org.apache.commons.lang3.StringUtils;

public final class CaptureEngineFactory {

    private CaptureEngineFactory() {}

    public static CaptureSession create(ClientOptions opts)
            throws Exception {

        boolean offline = StringUtils.isNotEmpty(opts.readFile);

        String deviceName = offline
                ? opts.readFile
                : StringUtils.isNotBlank(opts.adapter)
                ? opts.adapter
                : pickDefaultAdapter();

        if (!offline) {
            checkPermissions(deviceName);
        }

        CaptureEngine engine = offline
                ? CaptureEngine.openOffline(
                deviceName, opts.filter, opts.writeFile)
                : CaptureEngine.openLive(
                deviceName, opts.filter, opts.writeFile);

        String label = (offline ? "file " : "iface ")
                + deviceName
                + " [" + engine.linkTypeName() + "]";

        return new CaptureSession(engine, deviceName, label);
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
}
