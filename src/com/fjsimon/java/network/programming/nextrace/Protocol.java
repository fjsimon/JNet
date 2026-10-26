package com.fjsimon.java.network.programming.nextrace;

/** Upper layer protocols tracked by the application (mirrors sniffnet's Protocol). */
public enum Protocol {
    TCP,
    UDP,
    ICMP,
    ARP,
    /** Anything else observed on the wire (e.g. IGMP, IPv6 ext without transport, unknown ethertypes). */
    OTHER;

    public boolean isTrackedForConnections() {
        return this == TCP || this == UDP || this == ICMP || this == ARP;
    }

    /** Lower-case name used as key in the services database. */
    public String serviceKey() {
        return name().toLowerCase();
    }
}
