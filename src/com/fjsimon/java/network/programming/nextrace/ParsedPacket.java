package com.fjsimon.java.network.programming.nextrace;

import java.net.InetAddress;

/** Result of parsing a raw captured packet into network/transport level information. */
public final class ParsedPacket {
    public long timestampMicros;

    /** Number of bytes of the link-layer header (counted toward traffic). */
    public int linkHeaderBytes;

    public Protocol protocol;
    public InetAddress srcIp;
    public InetAddress dstIp;
    public int srcPort = -1;
    public int dstPort = -1;

    public String srcMac;
    public String dstMac;

    public int icmpType = -1;
    public int icmpCode = -1;

    public boolean arpRequest;
    public boolean arpReply;

    /** Bytes counted toward traffic statistics (link header + L3 length). */
    public long lengthBytes;

    /** Raw captured bytes, if export to PCAP is enabled. */
    public byte[] rawData;
}
