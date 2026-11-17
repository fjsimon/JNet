package main.java.com.fjsimon.jn3t.nextrace;

import main.java.com.fjsimon.jn3t.nextrace.capture.CaptureEngine;

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

        new CaptureApplication(opts).execute();
    }

}
