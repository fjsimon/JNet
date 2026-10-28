package com.fjsimon.java.network.programming.nextrace;

import java.net.InetAddress;

/** Canonical key of a network connection, normalized so local is always the first side. */
public record ConnectionKey(InetAddress localIp, int localPort, InetAddress remoteIp, int remotePort, Protocol protocol) {}
