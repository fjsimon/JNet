package com.fjsimon.java.network.programming;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class MacAddressUtils {

    public static void main(String[] args) {
        try {
            // Get the address for the localhost loopback interface (usually not the physical ethernet)
            InetAddress localHost = InetAddress.getLocalHost();
            System.out.println("Hostname: " + localHost.getHostName());
            System.out.println("IP Address: " + localHost.getHostAddress());

            // Iterate through all available network interfaces
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface ni = networkInterfaces.nextElement();
                byte[] hardwareAddress = ni.getHardwareAddress();

                if (hardwareAddress != null && hardwareAddress.length > 0) {
                    System.out.println("\nInterface Name: " + ni.getDisplayName());
                    System.out.println("MAC Address: " + formatMacAddress(hardwareAddress));
                    // You might add logic here to filter for a specific interface name, e.g.,
                    // "eth0", "en0", "Ethernet", if you have multiple interfaces.
                }
            }

        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    // Helper method to format the byte array as a readable MAC address string
    private static String formatMacAddress(byte[] mac) {
        if (mac == null || mac.length == 0) {
            return "";
        }

        return IntStream.range(0, mac.length)
                .mapToObj(i -> String.format("%02X", mac[i]))
                .collect(Collectors.joining(":"));
    }
}
