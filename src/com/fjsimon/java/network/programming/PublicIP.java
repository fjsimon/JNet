package com.fjsimon.java.network.programming;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class PublicIP {
    public static void main(String[] args) {
        try {

            HttpRequest request = HttpRequest
                    .newBuilder()
                    .uri(URI.create("https://ifconfig.me/ip"))
                    .GET()
                    .build();

            HttpResponse<String> response = HttpClient
                    .newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("Public IP: " + response.body().trim());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}