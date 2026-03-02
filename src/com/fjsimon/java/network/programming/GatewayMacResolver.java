package com.fjsimon.java.network.programming;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.concurrent.*;

public class GatewayMacResolver {

    private static final int READ_TIMEOUT = 5000;
    private static final int MAX_ATTEMPTS = 3;

    public static MacAddress resolve(PcapNetworkInterface nif, PcapHandle handle) throws Exception {
        Inet4Address gatewayIp = getDefaultGatewayIp();
        if (gatewayIp == null) {
            return MacAddress.ETHER_BROADCAST_ADDRESS;
        }

        MacAddress cachedMac = getGatewayMacFromArpCache(gatewayIp);
        if (cachedMac != null) {
            return cachedMac;
        }

        return resolveGatewayMacAddress(nif, handle);
    }

    public static MacAddress getGatewayMacFromArpCache(Inet4Address gatewayIp) {
        try {
            Process p = Runtime.getRuntime().exec("arp -n " + gatewayIp.getHostAddress());
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains(gatewayIp.getHostAddress())) {
                        String[] parts = line.split("\\s+");
                        for (String part : parts) {
                            if (part.contains(":")) {
                                return MacAddress.getByName(part);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    public static Inet4Address getDefaultGatewayIp() throws IOException {
        Process p = Runtime.getRuntime().exec("ip route show default");
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("default")) {
                    String[] parts = line.split("\\s+");
                    for (int i = 0; i < parts.length; i++) {
                        if (parts[i].equals("via")) {
                            return (Inet4Address) InetAddress.getByName(parts[i + 1]);
                        }
                    }
                }
            }
        }
        return null;
    }

    public static MacAddress getMacAddressFromNif(PcapNetworkInterface nif) {
        if (nif == null) return null;
        for (LinkLayerAddress addr : nif.getLinkLayerAddresses()) {
            if (addr instanceof MacAddress) {
                return (MacAddress) addr;
            }
        }
        return null;
    }

    public static MacAddress resolveGatewayMacAddress(PcapNetworkInterface nif, PcapHandle handle)
            throws Exception {

        Inet4Address localIp = null;
        for (PcapAddress pcapAddr : nif.getAddresses()) {
            InetAddress addr = pcapAddr.getAddress();
            if (addr instanceof Inet4Address) {
                localIp = (Inet4Address) addr;
                break;
            }
        }

        if (localIp == null) {
            return MacAddress.ETHER_BROADCAST_ADDRESS;
        }

        Inet4Address gatewayIp = getDefaultGatewayIp();
        if (gatewayIp == null) {
            return MacAddress.ETHER_BROADCAST_ADDRESS;
        }

        MacAddress localMac = getMacAddressFromNif(nif);
        if (localMac == null) {
            return MacAddress.ETHER_BROADCAST_ADDRESS;
        }

        return sendArpRequest(handle, localIp, localMac, gatewayIp);
    }

    private static MacAddress sendArpRequest(PcapHandle handle, Inet4Address srcIp, 
                                              MacAddress srcMac, Inet4Address dstIp) throws Exception {

        ArpPacket.Builder arpBuilder = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) 6)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(srcIp)
                .dstHardwareAddr(MacAddress.getByAddress(new byte[6]))
                .dstProtocolAddr(dstIp);

        EthernetPacket.Builder ethBuilder = new EthernetPacket.Builder()
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet arpRequest = ethBuilder.build();

        ExecutorService pool = Executors.newSingleThreadExecutor();

        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            handle.sendPacket(arpRequest);
            Future<Packet> future = pool.submit(() -> {
                while (true) {
                    Packet packet = handle.getNextPacketEx();
                    EthernetPacket ethPacket = packet.get(EthernetPacket.class);
                    if (ethPacket != null && ethPacket.getHeader().getType().value().equals(EtherType.ARP.value())) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        if (arp.getHeader().getOperation().equals(ArpOperation.REPLY) &&
                                arp.getHeader().getSrcProtocolAddr().equals(dstIp)) {
                            return packet;
                        }
                    }
                }
            });

            try {
                Packet reply = future.get(READ_TIMEOUT, TimeUnit.MILLISECONDS);
                ArpPacket arpReply = reply.get(ArpPacket.class);
                pool.shutdownNow();
                return (MacAddress) arpReply.getHeader().getSrcHardwareAddr();
            } catch (TimeoutException e) {
                future.cancel(true);
            }
        }

        pool.shutdownNow();
        return MacAddress.ETHER_BROADCAST_ADDRESS;
    }
}
