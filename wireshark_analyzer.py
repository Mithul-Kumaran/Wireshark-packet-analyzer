import pyshark
import sys
import os

def analyze_pcap(file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)

    print(f"📦 Analyzing: {file_path}")
    try:
        cap = pyshark.FileCapture(file_path, only_summaries=False)
    except Exception as e:
        print(f"⚠️ Error reading file: {e}")
        sys.exit(1)

    protocol_counts = {}
    dns_queries = []
    http_requests = []
    arp_map = {}
    arp_conflicts = []

    # === Packet Analysis ===
    for pkt in cap:
        try:
            # Count protocol usage
            proto = pkt.highest_layer
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            # DNS Analysis
            if 'DNS' in pkt and hasattr(pkt.dns, 'qry_name'):
                dns_queries.append(pkt.dns.qry_name)

            # HTTP Analysis
            if 'HTTP' in pkt:
                method = getattr(pkt.http, 'request_method', 'UNKNOWN')
                host = getattr(pkt.http, 'host', 'UNKNOWN')
                http_requests.append(f"{method} {host}")

            # ARP Analysis
            if 'ARP' in pkt:
                src_ip = getattr(pkt.arp, 'src_proto_ipv4', None)
                src_mac = getattr(pkt.arp, 'src_hw_mac', None)
                if src_ip and src_mac:
                    if src_ip in arp_map and arp_map[src_ip] != src_mac:
                        arp_conflicts.append((src_ip, arp_map[src_ip], src_mac))
                    else:
                        arp_map[src_ip] = src_mac
        except Exception:
            continue

    cap.close()

    # === Report Analysis ===
    dns_issue = bool(dns_queries)
    http_issue = bool(http_requests)
    arp_issue = len(arp_conflicts) > 0

    # === Report Writing ===
    report_lines = []
    report_lines.append("=== Wireshark Security Analysis Report ===\n")
    report_lines.append(f"File analyzed: {file_path}\n")

    # Protocol Summary
    report_lines.append("Protocols Detected:")
    for proto, count in protocol_counts.items():
        report_lines.append(f" - {proto}: {count} packets")
    report_lines.append("")

    # DNS
    report_lines.append("1. DNS Traffic:")
    if dns_issue:
        report_lines.append(" - Unencrypted DNS queries detected.")
        report_lines.append(" - Example Queries:")
        for q in list(set(dns_queries))[:5]:
            report_lines.append(f"   • {q}")
    else:
        report_lines.append(" - No DNS traffic detected.")
    report_lines.append("")

    # HTTP
    report_lines.append("2. HTTP Traffic:")
    if http_issue:
        report_lines.append(" - Unencrypted HTTP traffic detected.")
        report_lines.append(" - Sample HTTP Requests:")
        for r in http_requests[:5]:
            report_lines.append(f"   • {r}")
    else:
        report_lines.append(" - No HTTP traffic detected.")
    report_lines.append("")

    # ARP
    report_lines.append("3. ARP Analysis:")
    if arp_issue:
        report_lines.append(" - Possible ARP spoofing detected (same IP with multiple MACs):")
        for ip, mac1, mac2 in arp_conflicts[:5]:
            report_lines.append(f"   • {ip} → {mac1} AND {mac2}")
    else:
        report_lines.append(" - No ARP spoofing detected.")
    report_lines.append("")

    # Recommendations
    report_lines.append("=== Security Recommendations ===")
    if dns_issue:
        report_lines.append(" - Use DNS over TLS (DoT) or DNS over HTTPS (DoH).")
    if http_issue:
        report_lines.append(" - Upgrade services to HTTPS using valid TLS certificates.")
    if arp_issue:
        report_lines.append(" - Enable Dynamic ARP Inspection (DAI) or use static ARP tables.")
    report_lines.append(" - Segment network with VLANs to reduce attack surface.")
    report_lines.append("")

    # Save report
    with open("report.txt", "w") as f:
        f.write("\n".join(report_lines))

    print("✅ Analysis complete. Report saved as: report.txt")


# === Entry Point ===cd 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wireshark_analyzer.py <yourfile.pcapng>")
        sys.exit(1)

    analyze_pcap(sys.argv[1])
