package com.fjsimon.java.network.programming;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.io.Closeable;
import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

/**
 * Traceroute implementation using pcap4j.
 *
 * The probe is an ICMP Echo Request whose IPv4 TTL is increased hop by hop.
 * Each router on the path replies with an ICMP Time Exceeded message embedding
 * the original probe, letting us both identify the hop and its RTT.
 */
public class TraceroutePCAP4Jv3 implements Closeable {

    private static final int SNAPLEN = 65536;
    private static final int READ_TIMEOUT_MS = 100;
    private static final int MAX_HOPS = 30;
    private static final int PROBES_PER_HOP = 3;
    private static final long REPLY_WAIT_MS = 100;
    private static final short IDENTIFIER = (short) 1;

    private final Map<String, String> reverseCache = new ConcurrentHashMap<>();

    private final PcapHandle handle;
    private final Inet4Address source;
    private final Inet4Address target;
    private final MacAddress localMac;
    private final MacAddress gatewayMac;

    private final BlockingQueue<Packet> received = new LinkedBlockingQueue<>();
    private ExecutorService capturePool;
    private Future<?> captureFuture;

    private TraceroutePCAP4Jv3(PcapHandle handle, Inet4Address source, Inet4Address target,
                               MacAddress localMac, MacAddress gatewayMac) {
        this.handle = handle;
        this.source = source;
        this.target = target;
        this.localMac = localMac;
        this.gatewayMac = gatewayMac;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java TraceroutePCAP4J <hostname>");
            return;
        }

        String targetHost = args[0];
        Inet4Address target = resolveIpv4(targetHost);
        if (target == null) {
            System.err.println("Could not resolve '" + targetHost + "' to an IPv4 address.");
            return;
        }

        System.out.println("Traceroute to " + targetHost + " (" + target.getHostAddress() + "):\n");

        InterfaceInfo ifInfo = findSuitableInterface();
        if (ifInfo.nif == null) {
            System.err.println("Could not find a suitable network interface.");
            return;
        }
        System.out.println("Using interface: " + ifInfo.name() + "\n");

        MacAddress gatewayMac = resolveGatewayMac(ifInfo.nif);

        try (TraceroutePCAP4Jv3 traceroute = new TraceroutePCAP4Jv3(
                ifInfo.nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS),
                ifInfo.source,
                target,
                ifInfo.localMac,
                gatewayMac)) {

            traceroute.run();
        }
    }

    public void run() throws Exception {
        System.out.println("Source: " + source.getHostAddress());
        System.out.println("Local MAC: " + localMac);
        System.out.println("Gateway MAC: " + gatewayMac);

        setCaptureFilter();
        startCapture();
        try {
            System.out.println("Starting traceroute probes...\n");

            for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
                List<Long> rtts = new ArrayList<>();
                Inet4Address responder = null;
                boolean destReached = false;

                for (int probe = 1; probe <= PROBES_PER_HOP; probe++) {
                    long sendTime = System.nanoTime();
                    sendProbe(ttl);

                    ReplyResult result = waitForReply(ttl, sendTime);
                    if (result == null) {
                        rtts.add(null);
                    } else {
                        if (responder == null) {
                            responder = result.replyIp;
                        }
                        rtts.add(result.rttMs);
                        if (result.isDestination) {
                            destReached = true;
                        }
                    }
                }

                if (responder == null) {
                    System.out.printf("%2d  * * *%n", ttl);
                } else {
                    StringBuilder line = new StringBuilder(String.format("%2d  %s (%s)",
                            ttl, resolveHostName(responder), responder.getHostAddress()));
                    for (Long rtt : rtts) {
                        line.append(rtt == null
                                ? "  *"
                                : String.format("  %.3f ms", rtt / 1000.0));
                    }
                    System.out.println(line);
                }

                if (destReached) {
                    System.out.println();
                    System.out.println("Destination reached: " + target.getHostAddress());
                    return;
                }
            }

            System.out.println();
            System.out.println("Destination not reached within " + MAX_HOPS + " hops.");
        } finally {
            stopCapture();
        }
    }

    /**
     * Runs a blocking capture reader on a dedicated thread so received frames are
     * queued reliably. {@link PcapHandle#getNextPacketEx()} (blocking, with the
     * handle's read timeout) is used instead of {@code loop()} + listener, which
     * on some platforms never delivers packets.
     */
    private void startCapture() {
        capturePool = Executors.newSingleThreadExecutor();
        captureFuture = capturePool.submit(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        received.add(handle.getNextPacketEx());
                    } catch (TimeoutException e) {
                        // no frame within the handle read timeout; keep waiting
                    } catch (EOFException e) {
                        break;
                    }
                }
            } catch (Exception e) {
                if (!Thread.currentThread().isInterrupted()) {
                    System.err.println("  [capture loop ended] " + e.getMessage());
                }
            }
        });
    }

    private void stopCapture() {
        try {
            handle.breakLoop();
        } catch (Exception ignored) {
            // ignore
        }
        if (captureFuture != null) {
            try {
                captureFuture.get(1, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // ignore
            }
        }
        if (capturePool != null) {
            capturePool.shutdownNow();
        }
    }

    private void sendProbe(int ttl) throws Exception {
        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder()
                .identifier(IDENTIFIER)
                .sequenceNumber((short) ttl)
                .payloadBuilder(new UnknownPacket.Builder().rawData(new byte[32]));

        // Note: checksums are delegated so ICMP carries the same ID/sequence we match on.
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
                .identification((short) (Math.random() * Short.MAX_VALUE))
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(icmpBuilder);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(gatewayMac)
                .srcAddr(localMac)
                .type(EtherType.IPV4)
                .payloadBuilder(ipv4Builder)
                .paddingAtBuild(true);

        handle.sendPacket(etherBuilder.build());
    }

    /**
     * Reverse-resolves a hop IP to a hostname, like `traceroute` does in the "(ip)"
     * column. Uses a cache so each unique IP is resolved at most once.
     */
    private String resolveHostName(Inet4Address addr) {
        String ip = addr.getHostAddress();
        return reverseCache.computeIfAbsent(ip, key -> {
            try {
                String host = InetAddress.getByName(key).getHostName();
                if (host != null && !host.equalsIgnoreCase(key)) {
                    return host;
                }
            } catch (UnknownHostException ignored) {
                // no reverse name; fall back to the literal IP
            }
            return key;
        });
    }

    private ReplyResult waitForReply(int ttl, long sendTime) throws InterruptedException {
        long deadline = System.currentTimeMillis() + REPLY_WAIT_MS;

        while (true) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
                return null;
            }

            Packet packet = received.poll(remaining, TimeUnit.MILLISECONDS);
            if (packet == null) {
                return null;
            }

            ReplyResult result = classify(packet, ttl, sendTime);
            if (result != null) {
                return result;
            }
        }
    }

    /**
     * Decodes a captured frame into a usable traceroute result.
     * Only ICMPv4 replies that embed our own probe (matching identifier/sequence)
     * are accepted, so unrelated network noise is ignored.
     */
    private ReplyResult classify(Packet frame, int ttl, long sendTime) {
        IpV4Packet ip = toIpv4(frame);
        if (ip == null) {
            return null;
        }

        IcmpV4CommonPacket icmp = ip.get(IcmpV4CommonPacket.class);
        if (icmp == null) {
            return null;
        }

        ProbeInfo probe = findProbe(icmp);
        if (probe == null || probe.identifier != IDENTIFIER || probe.sequence != ttl) {
            return null;
        }

        Inet4Address responder = ip.getHeader().getSrcAddr();
        long rttMs = (System.nanoTime() - sendTime) / 1_000_000;
        IcmpV4Type type = icmp.getHeader().getType();

        if (type == IcmpV4Type.TIME_EXCEEDED) {
            return new ReplyResult(responder, rttMs, false);
        }
        if (type == IcmpV4Type.DESTINATION_UNREACHABLE) {
            return new ReplyResult(responder, rttMs, true);
        }
        if (type == IcmpV4Type.ECHO_REPLY) {
            return new ReplyResult(responder, rttMs, true);
        }
        return null;
    }

    /**
     * Re-parses the raw captured bytes as an Ethernet frame. On some platforms
     * (notably WiFi) pcap4j delivers captured frames as {@code UnknownPacket}
     * even though the link-layer type is Ethernet, so we decode the bytes
     * ourselves instead of trusting the handle's datalink mapping.
     */
    private static IpV4Packet toIpv4(Packet frame) {
        byte[] raw = frame.getRawData();
        if (raw == null) {
            return null;
        }
        try {
            return EthernetPacket.newPacket(raw, 0, raw.length).get(IpV4Packet.class);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Recursively walks the reply looking for the embedded ICMP probe
     * (either a direct Echo Reply or the original Echo Request carried
     * inside an error message).
     */
    private static ProbeInfo findProbe(Packet packet) {
        if (packet == null) {
            return null;
        }

        IcmpV4EchoReplyPacket reply = packet.get(IcmpV4EchoReplyPacket.class);
        if (reply != null) {
            return new ProbeInfo(reply.getHeader().getIdentifier(), reply.getHeader().getSequenceNumber());
        }

        IcmpV4EchoPacket echo = packet.get(IcmpV4EchoPacket.class);
        if (echo != null) {
            return new ProbeInfo(echo.getHeader().getIdentifier(), echo.getHeader().getSequenceNumber());
        }

        return findProbe(packet.getPayload());
    }

    private void setCaptureFilter() {
        String filter = "icmp";
        try {
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (Exception e) {
            System.err.println("Filter error: " + e.getMessage());
        }
    }

    private static InterfaceInfo findSuitableInterface() throws PcapNativeException {
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            InterfaceInfo info = toInterfaceInfo(nif);
            if (info != null) {
                return info;
            }
        }
        return null;
    }

    private static InterfaceInfo toInterfaceInfo(PcapNetworkInterface nif) {
        if (nif == null) {
            return null;
        }
        Inet4Address source = null;
        for (PcapAddress addr : nif.getAddresses()) {
            InetAddress ia = addr.getAddress();
            if (ia instanceof Inet4Address && !ia.isLoopbackAddress()) {
                source = (Inet4Address) ia;
                break;
            }
        }
        if (source == null) {
            return null;
        }

        // pcap4j may report a randomized (privacy) MAC on WiFi. Packets we craft
        // must use the real hardware address, otherwise peers address their replies
        // to a MAC nothing is listening on and we receive nothing back.
        MacAddress mac = resolveRealMac(source);
        if (mac == null) {
            mac = pcap4jMac(nif);
        }
        return new InterfaceInfo(nif, source, mac);
    }

    private static MacAddress resolveRealMac(Inet4Address addr) {
        try {
            java.net.NetworkInterface nif = java.net.NetworkInterface.getByInetAddress(addr);
            byte[] hw = nif.getHardwareAddress();
            if (hw != null && hw.length > 0) {
                return MacAddress.getByAddress(hw);
            }
        } catch (Exception ignored) {
            // fall through
        }
        return null;
    }

    private static MacAddress pcap4jMac(PcapNetworkInterface nif) {
        for (org.pcap4j.util.LinkLayerAddress lla : nif.getLinkLayerAddresses()) {
            if (lla instanceof MacAddress) {
                return (MacAddress) lla;
            }
        }
        return null;
    }

    private static MacAddress resolveGatewayMac(PcapNetworkInterface nif) throws Exception {
        System.out.print("Resolving gateway MAC... ");
        MacAddress mac = MacAddress.ETHER_BROADCAST_ADDRESS;
        try (PcapHandle probeHandle = nif.openLive(SNAPLEN,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS)) {
            MacAddress resolved = GatewayMacResolver.resolve(nif, probeHandle);
            if (resolved != null && !resolved.equals(MacAddress.ETHER_BROADCAST_ADDRESS)) {
                mac = resolved;
            }
        }
        System.out.println(" -> " + mac);
        return mac;
    }

    private static Inet4Address resolveIpv4(String host) throws UnknownHostException {
        for (InetAddress addr : InetAddress.getAllByName(host)) {
            if (addr instanceof Inet4Address) {
                return (Inet4Address) addr;
            }
        }
        return null;
    }

    @Override
    public void close() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    private static final class ReplyResult {
        final Inet4Address replyIp;
        final long rttMs;
        final boolean isDestination;

        ReplyResult(Inet4Address replyIp, long rttMs, boolean isDestination) {
            this.replyIp = replyIp;
            this.rttMs = rttMs;
            this.isDestination = isDestination;
        }
    }

    private static final class ProbeInfo {
        final short identifier;
        final short sequence;

        ProbeInfo(short identifier, short sequence) {
            this.identifier = identifier;
            this.sequence = sequence;
        }
    }

    private static final class InterfaceInfo {
        final PcapNetworkInterface nif;
        final Inet4Address source;
        final MacAddress localMac;

        InterfaceInfo(PcapNetworkInterface nif, Inet4Address source, MacAddress localMac) {
            this.nif = nif;
            this.source = source;
            this.localMac = localMac;
        }

        String name() {
            return nif.getName() + " (" + nif.getDescription() + ")";
        }
    }
}