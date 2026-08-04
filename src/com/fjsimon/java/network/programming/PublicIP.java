package com.fjsimon.java.network.programming;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class PublicIP {

    private static String getPublicIP() {
        try {
            URL url = new URL("https://ifconfig.me/ip");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
                return reader.readLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getPublicIPClient() {
        try {

            HttpRequest request = HttpRequest
                    .newBuilder()
                    .uri(URI.create("https://ifconfig.me/ip"))
                    .GET()
                    .build();

            HttpResponse<String> response = HttpClient
                    .newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());

            return response.body().trim();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {

        System.out.println("Public IP: " + getPublicIP());
        System.out.println("Public IP using http client: " + getPublicIPClient());
    }
}