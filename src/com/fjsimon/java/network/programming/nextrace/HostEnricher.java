package com.fjsimon.java.network.programming.nextrace;

/** Callback used to asynchronously enrich a host with ASN/country data. */
public interface HostEnricher {
    void enrich(HostStat host);
}

