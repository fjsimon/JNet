package com.fjsimon.java.network.programming.nextrace;

import java.nio.file.Path;

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

    private static void run(ClientOptions opts) {

        ServiceRegistry registry = new ServiceRegistry();
        GeoLookup geo = buildGeo(opts);


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
