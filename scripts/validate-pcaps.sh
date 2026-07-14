#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_DIR="${PROJECT_DIR}/shared/pcaps"
PASS=0
FAIL=0

check() {
    local name="$1"
    local pcap="$2"
    local filter="$3"
    local expected="$4"
    local actual

    if [ ! -f "$pcap" ]; then
        echo "  [FAIL] $name: pcap yok ($pcap)"
        FAIL=$((FAIL + 1))
        return
    fi

    actual=$(tshark -r "$pcap" -Y "$filter" 2>/dev/null | grep -vc "NA v2.0" || echo 0)

    if [ "$actual" -ge "$expected" ] 2>/dev/null; then
        echo "  [OK]   $name: $actual >= $expected"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name: $actual < $expected (filter: $filter)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Pcap Doğrulama ==="
echo ""

# M01 Basics
check "M01 HTTP"     "$PCAP_DIR/module-01-basics.pcap"       "http"                          1
check "M01 DNS"      "$PCAP_DIR/module-01-basics.pcap"       "dns"                           1
check "M01 ICMP"     "$PCAP_DIR/module-01-basics.pcap"       "icmp"                          1

# M03 ARP
check "M03 ARP Req"  "$PCAP_DIR/module-03-arp.pcap"          "arp.opcode == 1"               1
check "M03 ARP Rep"  "$PCAP_DIR/module-03-arp.pcap"          "arp.opcode == 2"               1

# M04 DHCP
check "M04 Discover" "$PCAP_DIR/module-04-dhcp.pcap"         "dhcp.option.dhcp == 1"         1
check "M04 Offer"    "$PCAP_DIR/module-04-dhcp.pcap"         "dhcp.option.dhcp == 2"         1
check "M04 ACK"      "$PCAP_DIR/module-04-dhcp.pcap"         "dhcp.option.dhcp == 5"         1

# M05 ICMP
check "M05 Echo Req" "$PCAP_DIR/module-05-icmp.pcap"         "icmp.type == 8"                5
check "M05 Echo Rep" "$PCAP_DIR/module-05-icmp.pcap"         "icmp.type == 0"                5

# M06 Fragmentation
check "M06 Fragment" "$PCAP_DIR/module-06-fragmentation.pcap" "ip.flags.mf == 1"             3

# M07 IPv6
check "M07 Echo Req" "$PCAP_DIR/module-07-ipv6.pcap"         "icmpv6.type == 128"            1
check "M07 NS"       "$PCAP_DIR/module-07-ipv6.pcap"         "icmpv6.type == 135"            1
check "M07 RA"       "$PCAP_DIR/module-07-ipv6.pcap"         "icmpv6.type == 134"            1
check "M07 AAAA"     "$PCAP_DIR/module-07-ipv6.pcap"         "dns.qry.type == 28"            1

# M08 TCP
check "M08 SYN"      "$PCAP_DIR/module-08-tcp.pcap"          "tcp.flags.syn == 1 && tcp.flags.ack == 0" 3
check "M08 SYN-ACK"  "$PCAP_DIR/module-08-tcp.pcap"          "tcp.flags.syn == 1 && tcp.flags.ack == 1" 1

# M09 TCP Sequence
check "M09 Retrans"  "$PCAP_DIR/module-09-tcp-sequence.pcap" "tcp.analysis.retransmission"   1
check "M09 DupACK"   "$PCAP_DIR/module-09-tcp-sequence.pcap" "tcp.analysis.duplicate_ack"    1

# M10 UDP
check "M10 UDP"      "$PCAP_DIR/module-10-udp.pcap"          "udp.port == 9090"              2
check "M10 PortUnr"  "$PCAP_DIR/module-10-udp.pcap"          "icmp.type == 3"                1

# M11 Advanced TCP
check "M11 Retrans"  "$PCAP_DIR/module-11-advanced-tcp.pcap" "tcp.analysis.retransmission"   3
check "M11 DupACK"   "$PCAP_DIR/module-11-advanced-tcp.pcap" "tcp.analysis.duplicate_ack"    3
check "M11 SACK"     "$PCAP_DIR/module-11-advanced-tcp.pcap" "tcp.options.sack"              3
check "M11 ZeroWin"  "$PCAP_DIR/module-11-advanced-tcp.pcap" "tcp.analysis.zero_window || tcp.window_size_value == 0" 1
check "M11 KeepAlive" "$PCAP_DIR/module-11-advanced-tcp.pcap" "tcp.analysis.keep_alive || tcp.analysis.keep_alive_ack" 1

# M12 DNS
check "M12 A"        "$PCAP_DIR/module-12-dns.pcap"          "dns.qry.type == 1"             1
check "M12 AAAA"     "$PCAP_DIR/module-12-dns.pcap"          "dns.qry.type == 28"            1
check "M12 NXDOMAIN" "$PCAP_DIR/module-12-dns.pcap"          "dns.flags.rcode == 3"          1
check "M12 Exfil"    "$PCAP_DIR/module-12-dns.pcap"          'dns.qry.name contains "exfil"' 1

# M13 HTTP
check "M13 GET"      "$PCAP_DIR/module-13-http.pcap"         "http.request.method == \"GET\"" 5
check "M13 POST"     "$PCAP_DIR/module-13-http.pcap"         "http.request.method == \"POST\"" 1
check "M13 403"      "$PCAP_DIR/module-13-http.pcap"         "http.response.code == 403"     1
check "M13 404"      "$PCAP_DIR/module-13-http.pcap"         "http.response.code == 404"     1
check "M13 SQLi"     "$PCAP_DIR/module-13-http.pcap"         "http.request.uri contains \"OR\" or http.request.uri contains \"UNION\"" 1

# M14 FTP
check "M14 USER"     "$PCAP_DIR/module-14-ftp.pcap"          'ftp.request.command == "USER"' 1
check "M14 PASS"     "$PCAP_DIR/module-14-ftp.pcap"          'ftp.request.command == "PASS"' 1
check "M14 230"      "$PCAP_DIR/module-14-ftp.pcap"          "ftp.response.code == 230"      1

# M15 Email
check "M15 SMTP"     "$PCAP_DIR/module-15-email.pcap"        "smtp"                          3
check "M15 POP3"     "$PCAP_DIR/module-15-email.pcap"        "pop"                           3
check "M15 IMAP"     "$PCAP_DIR/module-15-email.pcap"        "imap"                          2

# M16 TLS
check "M16 ClientHello" "$PCAP_DIR/module-16-tls.pcap"       "tls.handshake.type == 1"       1
check "M16 ServerHello" "$PCAP_DIR/module-16-tls.pcap"       "tls.handshake.type == 2"       1
check "M16 SNI"      "$PCAP_DIR/module-16-tls.pcap"          "tls.handshake.extensions_server_name" 1

# M19 TCP Graph
check "M19 TCP"      "$PCAP_DIR/module-19-tcp-graph.pcap"    "tcp"                           10
check "M19 Retrans"  "$PCAP_DIR/module-19-tcp-graph.pcap"    "tcp.analysis.retransmission"   1

# M20 Performance
check "M20 Retrans"  "$PCAP_DIR/module-20-performance.pcap"  "tcp.analysis.retransmission"   3

# M21 WLAN
check "M21 Beacon"   "$PCAP_DIR/module-21-wlan.pcap"         "wlan.fc.type_subtype == 8"     1
check "M21 EAPOL"    "$PCAP_DIR/module-21-wlan.pcap"         "eapol"                         1

# M22 VoIP
check "M22 SIP"      "$PCAP_DIR/module-22-voip.pcap"         "sip"                           5
check "M22 RTP"      "$PCAP_DIR/module-22-voip.pcap"         "rtp"                           10

# M23 Baseline
check "M23 TCP"      "$PCAP_DIR/module-23-baseline.pcap"     "tcp"                           5
check "M23 DNS"      "$PCAP_DIR/module-23-baseline.pcap"     "dns"                           1

# M24 Exam
check "M24 HTTP"     "$PCAP_DIR/module-24-exam-practice.pcap" "http"                         3
check "M24 FTP"      "$PCAP_DIR/module-24-exam-practice.pcap" "ftp"                          3
check "M24 SYN scan" "$PCAP_DIR/module-24-exam-practice.pcap" "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 172.50.2.200" 3
check "M24 Beacon"   "$PCAP_DIR/module-24-exam-practice.pcap" 'http.user_agent contains "Beacon"' 3

# M25 Forensics
check "M25 SQLi"     "$PCAP_DIR/module-25-forensics.pcap"    'http.request.uri contains "UNION"' 1
check "M25 XSS"      "$PCAP_DIR/module-25-forensics.pcap"    'http.request.uri contains "script"' 1
check "M25 POST"     "$PCAP_DIR/module-25-forensics.pcap"    'http.request.method == "POST"' 1
check "M25 Beacon"   "$PCAP_DIR/module-25-forensics.pcap"    'http.user_agent contains "Beacon"' 3
check "M25 Exfil"    "$PCAP_DIR/module-25-forensics.pcap"    'dns.qry.name contains "exfil"' 1

echo ""
echo "=== Sonuç: $PASS geçti, $FAIL başarısız ==="
[ "$FAIL" -eq 0 ] && echo "TÜM PCAP'LAR DOĞRULANDI" || exit 1
