package main.NetworkProgramming;

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
            InetAddress ip = InetAddress.getByName("www.google.co.uk");

            System.out.printf("Host Name %s%n", ip.getHostName());
            System.out.printf("IP Address %s%n", ip.getHostAddress());
            System.out.printf("Version %s%n", getVersion(ip));

        } catch (Exception e){
            e.printStackTrace();
        }
    }
}