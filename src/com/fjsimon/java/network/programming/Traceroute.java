package com.fjsimon.java.network.programming;

import java.io.*;
import java.net.*;
import java.util.*;

public class Traceroute {

    private static final int MAX_HOPS = 40; // Maximum number of hops (TTL)
    private static final int TIMEOUT = 5000; // Timeout for each packet in ms
    private static final int PORT = 33434;   // The UDP port used for traceroute

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java UDPSimulatedTraceroute <destination>");
            return;
        }

        String destination = args[0];

        try {
            InetAddress targetAddress = InetAddress.getByName(destination);
            System.out.println("Simulating Traceroute to " + targetAddress.getHostAddress() + " (" + destination + "):");

            // Loop over each hop (TTL value)
            for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
                long roundTripTime = sendUDPRequest(targetAddress, ttl, TIMEOUT);
                if (roundTripTime == -1) {
                    System.out.println(ttl + " * * * Request Timed Out");
                } else {
                    System.out.println(ttl + " " + roundTripTime + " ms");
                }

                // Stop when the destination is reached (if no timeout)
                if (roundTripTime != -1) {
                    System.out.println("Destination reached at hop " + ttl);
                    break;
                }
            }

        } catch (UnknownHostException e) {
            System.err.println("Error: Unknown host " + destination);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Send a UDP packet with a specific TTL and calculate round-trip time
    private static long sendUDPRequest(InetAddress targetAddress, int ttl, int timeout) {
        try {
            // Create a DatagramSocket
            MulticastSocket socket = new MulticastSocket();
            socket.setSoTimeout(timeout);  // Set the timeout for waiting for a response
            socket.setTimeToLive(ttl);     // Set the TTL for the packet

            // Prepare a simple message to send (this could be any data)
            byte[] buffer = new byte[512]; // Standard UDP size for traceroute
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, targetAddress, PORT);

            // Record the time before sending the packet
            long startTime = System.currentTimeMillis();

            // Send the UDP packet
            socket.send(packet);

            // Wait for the response (if it comes back)
            DatagramPacket responsePacket = new DatagramPacket(new byte[512], 512);
            socket.receive(responsePacket);

            long endTime = System.currentTimeMillis();
            socket.close();

            // Calculate and return the round-trip time
            return endTime - startTime;
        } catch (SocketTimeoutException e) {
            // No response received within the timeout period
            return -1;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }
}
