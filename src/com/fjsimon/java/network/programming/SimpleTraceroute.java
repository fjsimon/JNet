package com.fjsimon.java.network.programming;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import org.pcap4j.packet.IpV4Packet;

import java.net.*;

public class SimpleTraceroute {

    public static void main(String[] args) throws Exception {

        String targetHost = "google.com"; // Target
        InetAddress target = InetAddress.getByName(targetHost);
        InetAddress source = InetAddress.getLocalHost();

        System.out.println("Traceroute to " + targetHost + " (" + target.getHostAddress() + "):");

        // Find network device
        PcapNetworkInterface nif = Pcaps.findAllDevs().get(0); // Select the first device

        // Open the device
        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100);

        // Create ICMP packet (Echo Request)
        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder()
                .identifier((short) 1)
                .sequenceNumber((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData("data".getBytes()));

        IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder()
                .correctChecksumAtBuild(true)
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoBuilder);

        // Create the IPv4 Layer (Wrapper around ICMP)
        IpV4Packet.Builder ipv4Builder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .protocol(IpNumber.ICMPV4)
                .srcAddr((Inet4Address) source)
                .dstAddr((Inet4Address) target)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(icmpV4CommonBuilder)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0x00));

        // Create the Ethernet Layer (Wrapper around IPv4)
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .srcAddr(getLocalHostMacAddress())
                .dstAddr("getewayMacAddress")
                .type(EtherType.IPV4)
                .payloadBuilder(ipv4Builder)
                .paddingAtBuild(true);

        // Build the final, complete packet and send it
        Packet completePacket = etherBuilder.build();

        // Send the packet
        handle.sendPacket(completePacket);

        // Listen for ICMP Echo Reply
        Packet response = handle.getNextPacket();
        if (response != null) {
            System.out.println("Received reply: " + response);
        } else {
            System.out.println("No response received.");
        }

        // Close the handle
        handle.close();
    }

    private static MacAddress getLocalHostMacAddress() {
        try {
            // Use standard Java networking to get the raw bytes
            InetAddress localHost = InetAddress.getLocalHost();
            NetworkInterface networkInterface = NetworkInterface.getByInetAddress(localHost);

            if (networkInterface == null || networkInterface.getHardwareAddress() == null) {
                System.out.println("Could not find a valid physical MAC address for the local host.");
                return null;
            }

            byte[] macBytes = networkInterface.getHardwareAddress();
            return MacAddress.getByAddress(macBytes);
        } catch (UnknownHostException e) {
            System.err.println("Cannot resolve local host: " + e.getMessage());
        } catch (SocketException e) {
            System.err.println("Error accessing network interfaces: " + e.getMessage());
        }

        return null;
    }

}
