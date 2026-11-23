package main.java.com.fjsimon.jn3t.nextrace.tracking;

import main.java.com.fjsimon.jn3t.nextrace.model.HostStat;

/** Callback used to asynchronously enrich a host with ASN/country data. */
public interface HostEnricher {
    void enrich(HostStat host);
}

