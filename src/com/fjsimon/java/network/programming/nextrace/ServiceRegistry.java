package com.fjsimon.java.network.programming.nextrace;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Registry of upper-layer services mapped from port numbers, loaded from the
 * same services.txt database shipped with sniffnet (derived from nmap).
 */
public final class ServiceRegistry {

    private static final String RESOURCE = "/services.txt";

    private final Map<String, String> services = new HashMap<>(16000);

    public ServiceRegistry() {
        load();
    }

    private void load() {
        try (InputStream in = ServiceRegistry.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("missing resource " + RESOURCE);
            }
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            int parsed = 0;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int tab = line.indexOf('\t');
                if (tab <= 0) {
                    continue;
                }
                String name = line.substring(0, tab);
                String portProto = line.substring(tab + 1).trim();
                if (portProto.isEmpty() || name.isEmpty()) {
                    continue;
                }
                services.put(portProto, name);
                parsed++;
            }
            if (parsed == 0) {
                throw new IllegalStateException("no services loaded from " + RESOURCE);
            }
        } catch (Exception e) {
            throw new IllegalStateException("failed to load services database", e);
        }
    }

    /** Look up a service name for the given protocol and port, or null if unknown. */
    public String lookup(Protocol protocol, int port) {
        if (protocol != Protocol.TCP && protocol != Protocol.UDP) {
            return null;
        }
        if (port < 0 || port > 65535) {
            return null;
        }
        return services.get(port + "/" + protocol.serviceKey());
    }

    public int size() {
        return services.size();
    }
}

