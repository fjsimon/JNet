package com.fjsimon.java.network.programming.nextrace;

import com.maxmind.db.Reader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Asynchronous ASN / country enrichment backed by MaxMind GeoLite2 databases.
 * Uses the same GeoLite2-ASN.mmdb and GeoLite2-Country.mmdb files sniffnet ships.
 */
public final class GeoLookup implements HostEnricher {

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "geo-lookup");
        t.setDaemon(true);
        return t;
    });

    private final Reader asnReader;
    private final Reader countryReader;
    private final boolean enabled;

    private GeoLookup() {
        this.asnReader = null;
        this.countryReader = null;
        this.enabled = false;
    }

    private GeoLookup(Reader asn, Reader country) {
        this.asnReader = asn;
        this.countryReader = country;
        this.enabled = asn != null || country != null;
    }

    /** Create a disabled lookup. */
    public static GeoLookup disabled() {
        return new GeoLookup();
    }

    /** Load readers from the classpath (bundled databases). */
    public static GeoLookup fromClasspath() {
        Reader asn = openResource("/db/GeoLite2-ASN.mmdb");
        Reader country = openResource("/db/GeoLite2-Country.mmdb");
        return new GeoLookup(asn, country);
    }

    /** Create a GeoLookup from File objects. */
    public static GeoLookup fromFiles(File asnFile, File countryFile) {
        try {
            Reader asn = null, country = null;
            if (asnFile != null && asnFile.isFile()) {
                asn = new Reader(asnFile);
            }
            if (countryFile != null && countryFile.isFile()) {
                country = new Reader(countryFile);
            }
            return new GeoLookup(asn, country);
        } catch (IOException e) {
            throw new IllegalStateException("failed to load MMDB files", e);
        }
    }

    private static Reader openResource(String path) {
        try (InputStream in = GeoLookup.class.getResourceAsStream(path)) {
            if (in == null) {
                return null;
            }
            return new Reader(in);
        } catch (Exception e) {
            System.err.println("could not load MMDB " + path + ": " + e.getMessage());
            return null;
        }
    }

    public boolean enabled() {
        return enabled;
    }

    @Override
    public void enrich(HostStat host) {
        if (!enabled) {
            return;
        }
        try {
            executor.execute(() -> lookup(host));
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            // executor shut down while capture is still draining
        }
    }

    @SuppressWarnings("unchecked")
    private void lookup(HostStat host) {
        try {
            if (asnReader != null) {
                Object data = asnReader.get(host.ip, Object.class);
                if (data instanceof Map<?, ?> map) {
                    Object num = map.get("autonomous_system_number");
                    Object org = map.get("autonomous_system_organization");
                    if (num != null) host.asn = "AS" + num;
                    if (org != null) host.org = String.valueOf(org);
                }
            }
            if (countryReader != null) {
                Object data = countryReader.get(host.ip, Object.class);
                if (data instanceof Map<?, ?> map) {
                    Object countryObj = map.get("country");
                    if (countryObj instanceof Map<?, ?> country) {
                        Object iso = country.get("iso_code");
                        if (iso != null) host.country = String.valueOf(iso);
                    }
                }
            }
        } catch (Throwable e) {
            System.err.println("[geo-lookup] ip=" + host.ip + " error: " + e.getMessage());
        }
    }

    public void shutdown() {
        executor.shutdown();
        if (asnReader != null) {
            try {
                asnReader.close();
            } catch (IOException ignored) {
            }
        }
        if (countryReader != null) {
            try {
                countryReader.close();
            } catch (IOException ignored) {
            }
        }
    }
}

