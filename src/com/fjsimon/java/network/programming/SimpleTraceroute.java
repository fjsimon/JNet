package com.fjsimon.java.network.programming;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import java.net.InetAddress;

public class SimpleTraceroute {
    public static void main(String[] args) throws Exception {
        String targetHost = "google.com"; // Target
        InetAddress target = InetAddress.getByName(targetHost);
        System.out.println("Traceroute to " + targetHost + " (" + target.getHostAddress() + "):");

        // Find network device
        PcapNetworkInterface nif = Pcaps.findAllDevs().get(0); // Select the first device

        // Open the device
        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        // Create ICMP packet (Echo Request)
        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
        echoBuilder.identifier((short) 1)
                .sequenceNumber((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData("data".getBytes()));
        IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
        icmpV4CommonBuilder
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoBuilder);

        // Send the packet
        handle.sendPacket(icmpV4CommonBuilder.build());

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
}
