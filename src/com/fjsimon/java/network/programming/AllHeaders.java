package com.fjsimon.java.network.programming;

import java.io.*;
import java.net.*;

public class AllHeaders {

  public static void main(String[] args) {

    String[] arguments = {"http://www.google.co.uk"};

    for (int i = 0; i < arguments.length; i++) {
      try {
        URL u = new URL(arguments[i]);
        URLConnection uc = u.openConnection();
        for (int j = 1; ; j++) {
          String header = uc.getHeaderField(j);
          if (header == null) break;
          System.out.println(uc.getHeaderFieldKey(j) + ": " + header);
        }
      } catch (MalformedURLException ex) {
        System.err.println(args[i] + " is not a URL I understand.");
      } catch (IOException ex) {
        System.err.println(ex);
      }
      System.out.println();
    } 
  }
}