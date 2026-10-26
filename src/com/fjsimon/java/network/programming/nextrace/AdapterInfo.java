package com.fjsimon.java.network.programming.nextrace;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** Description of a network adapter available for sniffing. */
public final class AdapterInfo {
    public final String name;
    public final String description;
    public final List<InetAddress> addresses;

    public AdapterInfo(String name, String description, List<InetAddress> addresses) {
        this.name = name;
        this.description = description == null ? "" : description;
        this.addresses = new ArrayList<>(addresses);
    }

    public boolean isLoopback() {
        for (InetAddress a : addresses) {
            if (a.isLoopbackAddress()) {
                return true;
            }
        }
        return false;
    }

    public String displayAddresses() {
        if (addresses.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < addresses.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(addresses.get(i).getHostAddress());
        }
        return sb.toString();
    }
}
