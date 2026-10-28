package com.fjsimon.java.network.programming.nextrace;

import java.util.ArrayList;
import java.util.List;

/** Command-line options, mirroring sniffnet's CLI surface. */
public final class ClientOptions {

    public static final String VERSION = "0.0.1-SNAPSHOT";

    public String adapter;
    public boolean listAdapters;
    public String filter;
    public String readFile;
    public String writeFile;
    public String outputCsv;
    public boolean summary;
    public String mmdbDir;
    public boolean noGeo;
    public boolean help;
    public boolean version;

    public static String usage() {
        return """
                Usage: [sudo] java -jar jn3t.jar [OPTIONS]

                Comfortably monitor your network traffic from the terminal.
                (Java port of the sniffnet core: https://github.com/GyulyVGC/sniffnet)

                Options:
                  -a, --adapter <NAME>   network adapter to sniff (default: first non-loopback)
                  -l, --list-adapters    list available network adapters and exit
                  -f, --filter <BPF>     BPF filter to apply to the observed traffic
                                        (e.g. "tcp port 443" or "udp")
                  -r, --read <FILE>      read packets from a pcap/pcapng file instead of live capture
                  -w, --write <FILE>     export the captured packets to a pcap file
                  -o, --output <FILE>    write a CSV report of connections/hosts and exit
                  -s, --summary          print a summary to stdout instead of launching the TUI
                  -m, --mmdb-dir <DIR>   directory with GeoLite2-ASN.mmdb / GeoLite2-Country.mmdb
                                        (default: databases bundled with the application)
                  -n, --no-geo           disable ASN/country lookups
                  -h, --help             print this help and exit
                  -v, --version          print the version and exit

                In the TUI:
                  q  quit      p / space  pause  c  export CSV report
                """;
    }

    public static ClientOptions parse(String[] args) {
        ClientOptions o = new ClientOptions();
        List<String> rest = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-a":
                case "--adapter":
                    o.adapter = requireValue(args, ++i, a);
                    break;
                case "-f":
                case "--filter":
                    o.filter = requireValue(args, ++i, a);
                    break;
                case "-r":
                case "--read":
                    o.readFile = requireValue(args, ++i, a);
                    break;
                case "-w":
                case "--write":
                    o.writeFile = requireValue(args, ++i, a);
                    break;
                case "-o":
                case "--output":
                    o.outputCsv = requireValue(args, ++i, a);
                    break;
                case "-m":
                case "--mmdb-dir":
                    o.mmdbDir = requireValue(args, ++i, a);
                    break;
                case "-l":
                case "--list-adapters":
                    o.listAdapters = true;
                    break;
                case "-s":
                case "--summary":
                    o.summary = true;
                    break;
                case "-n":
                case "--no-geo":
                    o.noGeo = true;
                    break;
                case "-h":
                case "--help":
                    o.help = true;
                    break;
                case "-v":
                case "--version":
                    o.version = true;
                    break;
                default:
                    if (a.startsWith("--adapter=")) {
                        o.adapter = a.substring("--adapter=".length());
                    } else if (a.startsWith("--filter=")) {
                        o.filter = a.substring("--filter=".length());
                    } else if (a.startsWith("--read=")) {
                        o.readFile = a.substring("--read=".length());
                    } else if (a.startsWith("--write=")) {
                        o.writeFile = a.substring("--write=".length());
                    } else if (a.startsWith("--output=")) {
                        o.outputCsv = a.substring("--output=".length());
                    } else if (a.startsWith("--mmdb-dir=")) {
                        o.mmdbDir = a.substring("--mmdb-dir=".length());
                    } else {
                        rest.add(a);
                    }
            }
        }
        if (!rest.isEmpty()) {
            throw new IllegalArgumentException("unexpected argument: " + rest.get(0));
        }
        return o;
    }

    private static String requireValue(String[] args, int i, String flag) {
        if (i >= args.length) {
            throw new IllegalArgumentException("missing value for " + flag);
        }
        return args[i];
    }
}
