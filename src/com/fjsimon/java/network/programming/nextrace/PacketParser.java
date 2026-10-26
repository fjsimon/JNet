package com.fjsimon.java.network.programming.nextrace;

import java.net.InetAddress;
import java.util.Arrays;

/**
 * Byte-level packet parser for the link / network / transport headers.
 * Handles the same link types sniffnet supports (Ethernet II, Linux SLL, SLL2,
 * NULL/loopback, RAW) and IPv4/IPv6 with extension headers, TCP, UDP, ICMP, ARP.
 */
public final class PacketParser {

    private static final int ETHER_TYPE_IPV4 = 0x0800;
    private static final int ETHER_TYPE_IPV6 = 0x86DD;
    private static final int ETHER_TYPE_ARP = 0x0806;
    private static final int ETHER_TYPE_VLAN = 0x8100;
    private static final int ETHER_TYPE_QINQ = 0x88A8;
    private static final int ETHER_TYPE_QINQ2 = 0x9100;

    // DLT values
    public static final int DLT_NULL = 0;
    public static final int DLT_EN10MB = 1;
    public static final int DLT_LOOP = 12;
    public static final int DLT_RAW = 101;
    public static final int DLT_LINUX_SLL = 113;
    public static final int DLT_LINUX_SLL2 = 276;

    private PacketParser() {}

    /** Parse a raw captured packet. Returns null if the packet can't be parsed. */
    public static ParsedPacket parse(byte[] data, int dlt, long timestampMicros) {
        if (data == null || data.length == 0) {
            return null;
        }
        ParsedPacket p = new ParsedPacket();
        p.timestampMicros = timestampMicros;
        p.rawData = data;

        int offset = 0;
        int etherType;

        switch (dlt) {
            case DLT_NULL:
            case DLT_LOOP:
                if (data.length < 4) {
                    return null;
                }
                offset = 4;
                p.linkHeaderBytes = 4;
                etherType = ipVersionEtherType(data, offset);
                break;
            case DLT_EN10MB:
                if (data.length < 14) {
                    return null;
                }
                p.dstMac = macToString(data, 0);
                p.srcMac = macToString(data, 6);
                etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
                offset = 14;
                p.linkHeaderBytes = 14;
                while (offset + 4 <= data.length
                        && (etherType == ETHER_TYPE_VLAN
                        || etherType == ETHER_TYPE_QINQ
                        || etherType == ETHER_TYPE_QINQ2)) {
                    etherType = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                    offset += 4;
                    p.linkHeaderBytes += 4;
                }
                break;
            case DLT_LINUX_SLL:
                if (data.length < 16) {
                    return null;
                }
                etherType = ((data[14] & 0xFF) << 8) | (data[15] & 0xFF);
                offset = 16;
                p.linkHeaderBytes = 16;
                if (data.length >= 22 && (data[16] & 0xFF) != 0) {
                    // sender hardware address present (6 bytes)
                    p.srcMac = macToString(data, 16);
                }
                break;
            case DLT_LINUX_SLL2:
                if (data.length < 20) {
                    return null;
                }
                etherType = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
                offset = 20;
                p.linkHeaderBytes = 20;
                break;
            case DLT_RAW:
                offset = 0;
                p.linkHeaderBytes = 0;
                etherType = ipVersionEtherType(data, offset);
                break;
            default:
                // try to guess by first nibble
                etherType = ipVersionEtherType(data, offset);
                p.linkHeaderBytes = 0;
        }

        switch (etherType) {
            case ETHER_TYPE_ARP:
                if (!parseArp(data, offset, p)) {
                    return null;
                }
                p.protocol = Protocol.ARP;
                p.lengthBytes = p.linkHeaderBytes + Math.max(28, data.length - offset);
                return p;
            case ETHER_TYPE_IPV4:
                if (!parseIpv4(data, offset, p)) {
                    return null;
                }
                return p;
            case ETHER_TYPE_IPV6:
                if (!parseIpv6(data, offset, p)) {
                    return null;
                }
                return p;
            default:
                p.protocol = Protocol.OTHER;
                p.lengthBytes = p.linkHeaderBytes + (data.length - offset);
                return p;
        }
    }

    private static int ipVersionEtherType(byte[] data, int offset) {
        if (offset >= data.length) {
            return -1;
        }
        int version = (data[offset] & 0xF0) >>> 4;
        return version == 6 ? ETHER_TYPE_IPV6 : ETHER_TYPE_IPV4;
    }

    private static boolean parseIpv4(byte[] b, int o, ParsedPacket p) {
        if (o + 20 > b.length) {
            return false;
        }
        int ihl = (b[o] & 0x0F) * 4;
        if (o + ihl > b.length) {
            return false;
        }
        int totalLen = ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
        if (totalLen < ihl) {
            return false;
        }
        int protocolNum = b[o + 9] & 0xFF;
        p.srcIp = ip4(b, o + 12);
        p.dstIp = ip4(b, o + 16);
        p.lengthBytes = p.linkHeaderBytes + totalLen;
        return parseTransport(b, o + ihl, protocolNum, p);
    }

    private static boolean parseIpv6(byte[] b, int o, ParsedPacket p) {
        if (o + 40 > b.length) {
            return false;
        }
        int payloadLen = ((b[o + 4] & 0xFF) << 8) | (b[o + 5] & 0xFF);
        int nextHeader = b[o + 6] & 0xFF;
        p.srcIp = ip6(b, o + 8);
        p.dstIp = ip6(b, o + 24);
        p.lengthBytes = p.linkHeaderBytes + 40 + payloadLen;

        int offset = o + 40;
        int end = o + 40 + payloadLen;
        while (offset < end) {
            switch (nextHeader) {
                case 0: // hop-by-hop options
                case 43: // routing
                case 60: // destination options
                    if (offset + 2 > end) {
                        return true;
                    }
                    nextHeader = b[offset] & 0xFF;
                    offset += (b[offset + 1] & 0xFF) * 8 + 8;
                    break;
                case 44: // fragment
                    if (offset + 8 > end) {
                        return true;
                    }
                    nextHeader = b[offset] & 0xFF;
                    offset += 8;
                    break;
                case 51: // authentication header
                    if (offset + 2 > end) {
                        return true;
                    }
                    nextHeader = b[offset] & 0xFF;
                    offset += (b[offset + 1] & 0xFF) * 4 + 8;
                    break;
                default:
                    return parseTransport(b, offset, nextHeader, p);
            }
        }
        p.protocol = Protocol.OTHER;
        return true;
    }

    private static boolean parseTransport(byte[] b, int o, int protocolNum, ParsedPacket p) {
        switch (protocolNum) {
            case 6: // TCP
                p.protocol = Protocol.TCP;
                if (o + 4 <= b.length) {
                    p.srcPort = u16(b, o);
                    p.dstPort = u16(b, o + 2);
                }
                return true;
            case 17: // UDP
                p.protocol = Protocol.UDP;
                if (o + 4 <= b.length) {
                    p.srcPort = u16(b, o);
                    p.dstPort = u16(b, o + 2);
                }
                return true;
            case 1: // ICMPv4
            case 58: // ICMPv6
                p.protocol = Protocol.ICMP;
                if (o + 2 <= b.length) {
                    p.icmpType = b[o] & 0xFF;
                    p.icmpCode = b[o + 1] & 0xFF;
                }
                return true;
            default:
                p.protocol = Protocol.OTHER;
                return true;
        }
    }

    private static boolean parseArp(byte[] b, int o, ParsedPacket p) {
        if (o + 8 > b.length) {
            return false;
        }
        int ptype = u16(b, o + 2);
        int hlen = b[o + 4] & 0xFF;
        int plen = b[o + 5] & 0xFF;
        int op = u16(b, o + 6);
        if (ptype == ETHER_TYPE_IPV4 && plen == 4) {
            int spa = o + 8 + hlen;
            int tpa = o + 8 + 2 * hlen;
            if (tpa + 4 > b.length) {
                return false;
            }
            p.srcIp = ip4(b, spa);
            p.dstIp = ip4(b, tpa);
        } else if (ptype == ETHER_TYPE_IPV6 && plen == 16) {
            int spa = o + 8 + hlen;
            int tpa = o + 8 + 2 * hlen;
            if (tpa + 16 > b.length) {
                return false;
            }
            p.srcIp = ip6(b, spa);
            p.dstIp = ip6(b, tpa);
        } else {
            return false;
        }
        p.arpRequest = op == 1;
        p.arpReply = op == 2;
        return true;
    }

    private static int u16(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    private static InetAddress ip4(byte[] b, int o) {
        byte[] a = Arrays.copyOfRange(b, o, o + 4);
        try {
            return InetAddress.getByAddress(a);
        } catch (Exception e) {
            return null;
        }
    }

    private static InetAddress ip6(byte[] b, int o) {
        byte[] a = Arrays.copyOfRange(b, o, o + 16);
        try {
            return InetAddress.getByAddress(a);
        } catch (Exception e) {
            return null;
        }
    }

    private static String macToString(byte[] b, int o) {
        if (o + 6 > b.length) {
            return null;
        }
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02X", b[o + i]));
        }
        return sb.toString();
    }
}

