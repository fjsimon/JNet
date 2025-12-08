package com.fjsimon.java.network.programming;

import java.net.*;

public class AddressTests {

    public static int getVersion(InetAddress ia) {
        byte[] address = ia.getAddress();
        if (address.length == 4) return 4;
        else if (address.length == 16) return 6;
        else return -1;
    }

    public static void main(String[] args) {

        try {
            InetAddress address = InetAddress.getLocalHost();
            System.out.printf("Localhost: %s Version: %d \n", address, getVersion(address));

            address = InetAddress.getByName("www.google.co.uk");
            System.out.println(address);
            System.out.println("Host Address : " + address.getHostAddress());
            System.out.println("Host Name : " + address.getHostName());
            System.out.println("Canonical Hostname: " + address.getCanonicalHostName());

            InetAddress[] addresses = InetAddress.getAllByName("www.google.co.uk");
            for (InetAddress addr : addresses) {
                System.out.println(addr);
            }

            address = InetAddress.getLoopbackAddress();
            System.out.println("Loopback Address: " + address);

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }
}