package com.fjsimon.java.network.programming;

import java.net.*;

public class MulticastSocketTest {
    public static void main(String[] args) {
        try {
            // Create a multicast socket
            MulticastSocket socket = new MulticastSocket();

            // Set the TTL for multicast packets (how many hops)
            socket.setTimeToLive(128);  // TTL value (set to 128)

            // Prepare the message to send
            String message = "Hello, Multicast!";
            byte[] buffer = message.getBytes();

            // Multicast group address (e.g., 224.0.0.1 is a commonly used address)
            InetAddress group = InetAddress.getByName("233.1.1.1");

            // Datagram packet to send
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, group, 9876);  // Target group address and port

            // Send the multicast message
            socket.send(packet);
            System.out.println("Multicast message sent!");

            // Prepare to receive a multicast message
            byte[] receiveBuffer = new byte[1024];
            DatagramPacket responsePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);

            // Receive the response
            socket.receive(responsePacket);
            System.out.println("Received: " + new String(responsePacket.getData(), 0, responsePacket.getLength()));

            // Close the socket
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
