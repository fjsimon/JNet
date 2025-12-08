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
                NetworkInterface networkInterface = interfaces.nextElement();

                String name = networkInterface.getName();
                System.out.println("Name:"+name);

                String displayName = networkInterface.getDisplayName();
                System.out.println("Display name: "+displayName);

                int index = networkInterface.getIndex();
                System.out.println("Index: " + index);

                int hashCode = networkInterface.hashCode();
                System.out.println("Hashcode: "+ hashCode);

                System.out.println("\nInet address:");
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while(addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    System.out.println("InitAddress host address: " + address.getHostAddress());
                }
                System.out.println("\n");
            }
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }
}
