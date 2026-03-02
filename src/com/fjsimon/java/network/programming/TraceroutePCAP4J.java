package com.fjsimon.java.network.programming;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class TraceroutePCAP4J {

    private static final int TIMEOUT_MS = 3000;
    private static final int MAX_HOPS = 30;
    private static final short IDENTIFIER = (short) 1;
    private static final int BASE_PORT = 65536;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java TraceroutePCAP4J <hostname>");
            return;
        }

        String targetHost = args[0];
        Inet4Address target = (Inet4Address) InetAddress.getByName(targetHost);

        System.out.println("Traceroute to " + targetHost + " (" + target.getHostAddress() + "):\n");

        PcapNetworkInterface nif = findSuitableNetworkInterface(target);
        if (nif == null) {
            System.err.println("Could not find a suitable network interface.");
            return;
        }

        System.out.println("Using interface: " + nif.getName() + " (" + nif.getName() + ")\n");

        Inet4Address source = getSourceAddress(nif, target);
        MacAddress localMac = getLocalMacAddress(nif);

        System.out.println("Source: " + source.getHostAddress());
        System.out.println("Local MAC: " + (localMac != null ? localMac : "null"));

        PcapHandle handle = nif.openLive(BASE_PORT, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT_MS);
        handle.setBlockingMode(PcapHandle.BlockingMode.NONBLOCKING);

        System.out.println("Resolving gateway MAC...");
        MacAddress gatewayMac = GatewayMacResolver.resolve(nif, handle);

        if (gatewayMac == null) {
            System.err.println("Failed to resolve gateway MAC address. Using broadcast.");
            gatewayMac = MacAddress.ETHER_BROADCAST_ADDRESS;
        }

        System.out.println("Gateway MAC: " + gatewayMac);

        InetAddress local = InetAddress.getLocalHost();
        setFilter(handle, target, source, local);

        System.out.println("Starting traceroute probes...");

        for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
            System.out.println("Sending probe with TTL=" + ttl + "...");
            sendProbe(handle, source, target, localMac, gatewayMac, ttl);
            System.out.println("Probe sent, waiting for reply...");

            try { Thread.sleep(100); } catch (InterruptedException e) {}

            ReplyResult result = waitForReply(handle, ttl, target);

            if (result == null) {
                System.out.printf("%2d  * * *\n", ttl);
            } else {
                System.out.printf("%2d  %4d ms  %s\n", ttl, result.rtt, result.replyIp.getHostAddress());

                if (result.isDestination) {
                    System.out.println("\nDestination reached!");
                    break;
                }
            }
        }

        handle.close();
        System.out.println("\nTraceroute complete.");
    }

    private static PcapNetworkInterface findSuitableNetworkInterface(InetAddress target) throws PcapNativeException {
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            for (PcapAddress addr : nif.getAddresses()) {
                InetAddress ia = addr.getAddress();
                if (ia instanceof Inet4Address && !ia.isLoopbackAddress()) {
                    return nif;
                }
            }
        }
        return Pcaps.findAllDevs().get(0);
    }

    private static Inet4Address getSourceAddress(PcapNetworkInterface nif, InetAddress target) throws UnknownHostException {
        for (PcapAddress addr : nif.getAddresses()) {
            InetAddress ia = addr.getAddress();
            if (ia instanceof Inet4Address && !ia.isLoopbackAddress()) {
                return (Inet4Address) ia;
            }
        }
        return (Inet4Address) InetAddress.getLocalHost();
    }

    private static MacAddress getLocalMacAddress(PcapNetworkInterface nif) {
        for (org.pcap4j.util.LinkLayerAddress lla : nif.getLinkLayerAddresses()) {
            if (lla instanceof MacAddress) {
                return (MacAddress) lla;
            }
        }
        return null;
    }

    private static void setFilter(PcapHandle handle, InetAddress target, InetAddress source, InetAddress local) throws NotOpenException {
        try {
            handle.setFilter("(icmp and (dst host " + source.getHostAddress() + " or dst host " + local.getHostAddress() + ")) or (udp and (dst host " + source.getHostAddress() + " or dst host " + local.getHostAddress() + "))", BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (Exception e) {
            System.err.println("Filter error: " + e.getMessage());
        }
    }

    private static void sendProbe(PcapHandle handle, Inet4Address source, Inet4Address target,
                                   MacAddress srcMac, MacAddress dstMac, int ttl) throws NotOpenException, PcapNativeException {
        
        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder()
            .identifier(IDENTIFIER)
            .sequenceNumber((short) ttl)
            .payloadBuilder(new UnknownPacket.Builder().rawData(new byte[32]));

        IcmpV4CommonPacket.Builder icmpBuilder = new IcmpV4CommonPacket.Builder()
            .type(IcmpV4Type.ECHO)
            .code(IcmpV4Code.NO_CODE)
            .payloadBuilder(echoBuilder)
            .correctChecksumAtBuild(true);

        IpV4Packet.Builder ipv4Builder = new IpV4Packet.Builder()
            .version(IpVersion.IPV4)
            .protocol(IpNumber.ICMPV4)
            .ttl((byte) ttl)
            .dstAddr(target)
            .srcAddr(source)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(icmpBuilder)
            .identification((short) (Math.random() * Short.MAX_VALUE))
            .tos(IpV4Rfc791Tos.newInstance((byte) 0));

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
            .dstAddr(dstMac)
            .srcAddr(srcMac)
            .type(EtherType.IPV4)
            .payloadBuilder(ipv4Builder)
            .paddingAtBuild(true);

        handle.sendPacket(etherBuilder.build());
    }

    private static ReplyResult waitForReply(PcapHandle handle, int ttl, Inet4Address target) {
        long startTime = System.currentTimeMillis();
        int maxWait = 2000;
        int packetsSeen = 0;

        while (System.currentTimeMillis() - startTime < maxWait) {
            Packet packet;
            try {
                packet = handle.getNextPacket();
            } catch (Exception e) {
                try { Thread.sleep(50); } catch (InterruptedException ie) { break; }
                continue;
            }

            if (packet == null) {
                try { Thread.sleep(50); } catch (InterruptedException e) { break; }
                continue;
            }

            packetsSeen++;
            if (packetsSeen <= 3) {
                System.out.println("  Got packet #" + packetsSeen);
                byte[] raw = packet.getRawData();
                if (raw != null && raw.length >= 34) {
                    int srcIp = ((raw[26] & 0xFF) << 24 | (raw[27] & 0xFF) << 16 | (raw[28] & 0xFF) << 8 | (raw[29] & 0xFF));
                    int dstIp = ((raw[30] & 0xFF) << 24 | (raw[31] & 0xFF) << 16 | (raw[32] & 0xFF) << 8 | (raw[33] & 0xFF));
                    String srcIpStr = ((srcIp >> 24) & 0xFF) + "." + ((srcIp >> 16) & 0xFF) + "." + ((srcIp >> 8) & 0xFF) + "." + (srcIp & 0xFF);
                    String dstIpStr = ((dstIp >> 24) & 0xFF) + "." + ((dstIp >> 16) & 0xFF) + "." + ((dstIp >> 8) & 0xFF) + "." + (dstIp & 0xFF);
                    byte proto = raw[23];
                    boolean isOutgoing = false;
                    try {
                        java.net.InetAddress local = java.net.InetAddress.getLocalHost();
                        isOutgoing = srcIpStr.equals(local.getHostAddress());
                    } catch (Exception e) {}
                    System.out.println("    " + (isOutgoing ? "OUT" : "IN") + " IP: " + srcIpStr + " -> " + dstIpStr + " proto=" + (proto & 0xFF));
                    if (proto == 17 && raw.length >= 42) {
                        int srcPort = ((raw[34] & 0xFF) << 8 | (raw[35] & 0xFF));
                        int dstPort = ((raw[36] & 0xFF) << 8 | (raw[37] & 0xFF));
                        System.out.println("    UDP: srcPort=" + srcPort + " dstPort=" + dstPort);
                    }
                    if (proto == 1 && raw.length >= 30) {
                        byte icmpType = raw[34];
                        System.out.println("    ICMP type: " + (icmpType & 0xFF));
                    }
                }
            }

            try {
                byte[] raw = packet.getRawData();
                if (raw == null || raw.length < 34) continue;

                byte proto = raw[23];
                if (proto != 1) continue;

                int srcIp = ((raw[26] & 0xFF) << 24 | (raw[27] & 0xFF) << 16 | (raw[28] & 0xFF) << 8 | (raw[29] & 0xFF));
                String srcIpStr = ((srcIp >> 24) & 0xFF) + "." + ((srcIp >> 16) & 0xFF) + "." + ((srcIp >> 8) & 0xFF) + "." + (srcIp & 0xFF);

                if (packetsSeen <= 3) {
                    System.out.println("    Src IP: " + srcIpStr + ", Proto: ICMP");
                }

                if (raw.length < 36) continue;
                byte icmpType = raw[34];
                long rtt = System.currentTimeMillis() - startTime;

                if (packetsSeen <= 3) {
                    System.out.println("    ICMP type: " + (icmpType & 0xFF));
                }

                if (icmpType == 11) {
                    System.out.println("    TIME_EXCEEDED from " + srcIpStr);
                    return new ReplyResult(InetAddress.getByName(srcIpStr), rtt, false);
                } else if (icmpType == 3) {
                    if (srcIpStr.equals(target.getHostAddress())) {
                        System.out.println("    DESTINATION_UNREACHABLE - destination reached!");
                        return new ReplyResult(InetAddress.getByName(srcIpStr), rtt, true);
                    }
                } else if (icmpType == 0) {
                    if (srcIpStr.equals(target.getHostAddress())) {
                        System.out.println("    ECHO_REPLY - destination reached!");
                        return new ReplyResult(InetAddress.getByName(srcIpStr), rtt, true);
                    }
                }
            } catch (Exception e) {
                System.out.println("    [ERROR] " + e.getMessage());
            }
        }

        return null;
    }

    private static class ReplyResult {
        final InetAddress replyIp;
        final long rtt;
        final boolean isDestination;

        ReplyResult(InetAddress replyIp, long rtt, boolean isDestination) {
            this.replyIp = replyIp;
            this.rtt = rtt;
            this.isDestination = isDestination;
        }
    }
}
