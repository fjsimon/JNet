package com.fjsimon.java.network.programming;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public class NetworkInterfaceLocal {

    public static void main(String[] args) {

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while(interfaces.hasMoreElements()) {
                NetworkInterface intf = interfaces.nextElement();
                System.out.println("NetworkInterface display name: " + intf.getDisplayName());
                Enumeration<InetAddress> addresses = intf.getInetAddresses();
                while(addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    System.out.println("InitAddress host address: " + address.getHostAddress());
                }
            }
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }
}
