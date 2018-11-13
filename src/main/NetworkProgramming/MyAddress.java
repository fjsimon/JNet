package main.NetworkProgramming;

import java.net.*;

public class MyAddress {

  public static void main (String[] args) {

    try {
      InetAddress address = InetAddress.getLocalHost();
      System.out.println(address);
      System.out.printf("Host Address: %s%n", address.getHostAddress());
      System.out.printf("Host Name: %s%n", address.getHostName());
    } catch (UnknownHostException ex) {
      System.out.println("Could not find this computer's address.");
    }
  }
}
