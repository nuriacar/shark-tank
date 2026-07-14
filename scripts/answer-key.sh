#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PCAP_DIR="$PROJECT_DIR/shared/pcaps"
OUTPUT="$PCAP_DIR/answer-key.txt"

if ! command -v tshark &>/dev/null; then
    echo "HATA: tshark bulunamadı. Wireshark/tshark kurulu olduğundan emin olun." >&2
    exit 1
fi

if ! command -v capinfos &>/dev/null; then
    echo "HATA: capinfos bulunamadı. Wireshark/tshark kurulu olduğundan emin olun." >&2
    exit 1
fi

{
    echo "=== Shark-Tank Cevap Anahtarı ==="
    echo "Oluşturulma: $(date)"
    echo ""

    # --- Modül 01: Temel Bilgiler ---
    if [[ -f "$PCAP_DIR/module-01-basics.pcap" ]]; then
        echo "--- Modül 01: Temel Bilgiler ---"
        total_pkts=$(capinfos -c "$PCAP_DIR/module-01-basics.pcap" 2>/dev/null | grep -i "packets" | awk '{print $NF}' | tr -d ' ')
        echo "Toplam paket sayısı: ${total_pkts:-N/A}"
        proto_count=$(tshark -r "$PCAP_DIR/module-01-basics.pcap" -T fields -e frame.protocols 2>/dev/null | tr ':' '\n' | sort -u | wc -l | tr -d ' ')
        echo "Protokol çeşidi sayısı: ${proto_count:-N/A}"
        first_pkt_time=$(tshark -r "$PCAP_DIR/module-01-basics.pcap" -T fields -e frame.time_relative -c 1 2>/dev/null | tr -d ' ')
        echo "İlk paket zamanı (relative): ${first_pkt_time:-N/A}"
        echo ""
    else
        echo "--- Modül 01: Temel Bilgiler ---"
        echo "UYARI: module-01-basics.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 03: ARP ---
    if [[ -f "$PCAP_DIR/module-03-arp.pcap" ]]; then
        echo "--- Modül 03: ARP ---"
        arp_packets=$(tshark -r "$PCAP_DIR/module-03-arp.pcap" -Y "arp" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam ARP paketi: ${arp_packets:-N/A}"
        arp_request=$(tshark -r "$PCAP_DIR/module-03-arp.pcap" -Y "arp.opcode == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "ARP Request: ${arp_request:-N/A}"
        arp_reply=$(tshark -r "$PCAP_DIR/module-03-arp.pcap" -Y "arp.opcode == 2" 2>/dev/null | wc -l | tr -d ' ')
        echo "ARP Reply: ${arp_reply:-N/A}"
        arp_sender_ip=$(tshark -r "$PCAP_DIR/module-03-arp.pcap" -Y "arp" -T fields -e arp.src.proto_ipv4 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "ARP gönderen IP'ler: ${arp_sender_ip:-N/A}"
        arp_sender_mac=$(tshark -r "$PCAP_DIR/module-03-arp.pcap" -Y "arp" -T fields -e arp.src.hw_mac 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "ARP gönderen MAC'ler: ${arp_sender_mac:-N/A}"
        echo ""
    else
        echo "--- Modül 03: ARP ---"
        echo "UYARI: module-03-arp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 04: DHCP ---
    if [[ -f "$PCAP_DIR/module-04-dhcp.pcap" ]]; then
        echo "--- Modül 04: DHCP ---"
        dhcp_packets=$(tshark -r "$PCAP_DIR/module-04-dhcp.pcap" -Y "dhcp" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam DHCP paketi: ${dhcp_packets:-N/A}"
        dhcp_offered_ip=$(tshark -r "$PCAP_DIR/module-04-dhcp.pcap" -Y "dhcp.option.dhcp == 2" -T fields -e dhcp.ip.client 2>/dev/null | head -1)
        echo "DHCP teklif edilen IP: ${dhcp_offered_ip:-N/A}"
        dhcp_server=$(tshark -r "$PCAP_DIR/module-04-dhcp.pcap" -Y "dhcp.option.domain_name_server" -T fields -e dhcp.option.domain_name_server 2>/dev/null | head -1)
        echo "DHCP DNS sunucusu: ${dhcp_server:-N/A}"
        dhcp_lease=$(tshark -r "$PCAP_DIR/module-04-dhcp.pcap" -Y "dhcp.option.dhcp == 2" -T fields -e dhcp.option.ip_address_lease_time 2>/dev/null | head -1)
        echo "DHCP kiralama süresi (sn): ${dhcp_lease:-N/A}"
        echo ""
    else
        echo "--- Modül 04: DHCP ---"
        echo "UYARI: module-04-dhcp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 05: ICMP ---
    if [[ -f "$PCAP_DIR/module-05-icmp.pcap" ]]; then
        echo "--- Modül 05: ICMP ---"
        echo "Echo Request sayısı: $(tshark -r "$PCAP_DIR/module-05-icmp.pcap" -Y "icmp.type == 8" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
        echo "Echo Reply sayısı: $(tshark -r "$PCAP_DIR/module-05-icmp.pcap" -Y "icmp.type == 0" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
        rtt_values=$(tshark -r "$PCAP_DIR/module-05-icmp.pcap" -Y "icmp.type == 0" -T fields -e icmp.resptime 2>/dev/null | grep -v '^$' || true)
        if [[ -n "$rtt_values" ]]; then
            avg_rtt=$(echo "$rtt_values" | awk '{sum+=$1; count++} END {if(count>0) printf "%.6f", sum/count; else print "N/A"}')
        else
            avg_rtt="N/A"
        fi
        echo "Ortalama RTT: $avg_rtt saniye"
        time_exceeded=$(tshark -r "$PCAP_DIR/module-05-icmp.pcap" -Y "icmp.type == 11" 2>/dev/null | wc -l | tr -d ' ')
        echo "Time Exceeded (TTL aşımı) sayısı: ${time_exceeded:-N/A}"
        icmp_tunnel=$(tshark -r "$PCAP_DIR/module-05-icmp.pcap" -Y "icmp.type == 8 && data.len > 48" 2>/dev/null | wc -l | tr -d ' ')
        echo "Büyük data içeren Echo Request (tunneling): ${icmp_tunnel:-N/A}"
        icmp_sources=$(tshark -r "$PCAP_DIR/module-05-icmp.pcap" -Y "icmp" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "ICMP gönderen IP'ler: ${icmp_sources:-N/A}"
        echo ""
    else
        echo "--- Modül 05: ICMP ---"
        echo "UYARI: module-05-icmp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 06: IP Fragmentation ---
    if [[ -f "$PCAP_DIR/module-06-fragmentation.pcap" ]]; then
        echo "--- Modül 06: IP Fragmentation ---"
        frag_packets=$(tshark -r "$PCAP_DIR/module-06-fragmentation.pcap" -Y "ip.flags.mf == 1 or ip.frag_offset > 0" 2>/dev/null | wc -l | tr -d ' ')
        echo "Fragmente edilmiş IP paketi: ${frag_packets:-N/A}"
        mf_packets=$(tshark -r "$PCAP_DIR/module-06-fragmentation.pcap" -Y "ip.flags.mf == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "More Fragments bayraklı: ${mf_packets:-N/A}"
        df_packets=$(tshark -r "$PCAP_DIR/module-06-fragmentation.pcap" -Y "ip.flags.df == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "Don't Fragment bayraklı: ${df_packets:-N/A}"
        max_frag_offset=$(tshark -r "$PCAP_DIR/module-06-fragmentation.pcap" -Y "ip.frag_offset > 0" -T fields -e ip.frag_offset 2>/dev/null | sort -n | tail -1 || true)
        echo "En yüksek fragment offset: ${max_frag_offset:-N/A}"
        echo ""
    else
        echo "--- Modül 06: IP Fragmentation ---"
        echo "UYARI: module-06-fragmentation.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 07: IPv6 ---
    if [[ -f "$PCAP_DIR/module-07-ipv6.pcap" ]]; then
        echo "--- Modül 07: IPv6 ---"
        ipv6_packets=$(tshark -r "$PCAP_DIR/module-07-ipv6.pcap" -Y "ipv6" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam IPv6 paketi: ${ipv6_packets:-N/A}"
        icmpv6_types=$(tshark -r "$PCAP_DIR/module-07-ipv6.pcap" -Y "icmpv6" -T fields -e icmpv6.type 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "ICMPv6 türleri: ${icmpv6_types:-N/A}"
        echo ""
    else
        echo "--- Modül 07: IPv6 ---"
        echo "UYARI: module-07-ipv6.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 08: TCP ---
    if [[ -f "$PCAP_DIR/module-08-tcp.pcap" ]]; then
        echo "--- Modül 08: TCP ---"
        first_syn_isn=$(tshark -r "$PCAP_DIR/module-08-tcp.pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.seq_raw -c 1 2>/dev/null | tr -d ' ')
        echo "İlk SYN ISN: ${first_syn_isn:-N/A}"
        syn_packets=$(tshark -r "$PCAP_DIR/module-08-tcp.pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" 2>/dev/null | wc -l | tr -d ' ')
        echo "SYN paketi sayısı: ${syn_packets:-N/A}"
        psh_packets=$(tshark -r "$PCAP_DIR/module-08-tcp.pcap" -Y "tcp.flags.push == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "PSH bayraklı paket sayısı: ${psh_packets:-N/A}"
        urg_packets=$(tshark -r "$PCAP_DIR/module-08-tcp.pcap" -Y "tcp.flags.urg == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "URG bayraklı paket sayısı: ${urg_packets:-N/A}"
        rst_packets=$(tshark -r "$PCAP_DIR/module-08-tcp.pcap" -Y "tcp.flags.reset == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "RST bayraklı paket sayısı: ${rst_packets:-N/A}"
        tcp_connections=$(tshark -r "$PCAP_DIR/module-08-tcp.pcap" -T fields -e tcp.stream 2>/dev/null | sort -u | wc -l | tr -d ' ')
        echo "TCP akış sayısı (stream): ${tcp_connections:-N/A}"
        echo ""
    else
        echo "--- Modül 08: TCP ---"
        echo "UYARI: module-08-tcp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 09: TCP Dizi Analizi ---
    if [[ -f "$PCAP_DIR/module-09-tcp-sequence.pcap" ]]; then
        echo "--- Modül 09: TCP Dizi Analizi ---"
        retransmissions=$(tshark -r "$PCAP_DIR/module-09-tcp-sequence.pcap" -Y "tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')
        echo "Retransmission sayısı: ${retransmissions:-N/A}"
        dup_acks=$(tshark -r "$PCAP_DIR/module-09-tcp-sequence.pcap" -Y "tcp.analysis.duplicate_ack" 2>/dev/null | wc -l | tr -d ' ')
        echo "Duplicate ACK sayısı: ${dup_acks:-N/A}"
        fast_retrans=$(tshark -r "$PCAP_DIR/module-09-tcp-sequence.pcap" -Y "tcp.analysis.fast_retransmission" 2>/dev/null | wc -l | tr -d ' ')
        echo "Fast Retransmission sayısı: ${fast_retrans:-N/A}"
        zero_window=$(tshark -r "$PCAP_DIR/module-09-tcp-sequence.pcap" -Y "tcp.analysis.zero_window" 2>/dev/null | wc -l | tr -d ' ')
        echo "Zero Window olayı: ${zero_window:-N/A}"
        sack_packets=$(tshark -r "$PCAP_DIR/module-09-tcp-sequence.pcap" -Y "tcp.options.sack" 2>/dev/null | wc -l | tr -d ' ')
        echo "SACK içeren paket: ${sack_packets:-N/A}"
        echo ""
    else
        echo "--- Modül 09: TCP Dizi Analizi ---"
        echo "UYARI: module-09-tcp-sequence.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 10: UDP ---
    if [[ -f "$PCAP_DIR/module-10-udp.pcap" ]]; then
        echo "--- Modül 10: UDP ---"
        udp_packets=$(tshark -r "$PCAP_DIR/module-10-udp.pcap" -Y "udp" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam UDP paketi: ${udp_packets:-N/A}"
        udp_ports=$(tshark -r "$PCAP_DIR/module-10-udp.pcap" -Y "udp" -T fields -e udp.dstport 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "UDP hedef portlar: ${udp_ports:-N/A}"
        dns_over_udp=$(tshark -r "$PCAP_DIR/module-10-udp.pcap" -Y "dns" 2>/dev/null | wc -l | tr -d ' ')
        echo "DNS (UDP) paketi: ${dns_over_udp:-N/A}"
        echo ""
    else
        echo "--- Modül 10: UDP ---"
        echo "UYARI: module-10-udp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 11: İleri TCP Analizi ---
    if [[ -f "$PCAP_DIR/module-11-advanced-tcp.pcap" ]]; then
        echo "--- Modül 11: İleri TCP Analizi ---"
        tcp_packets_m11=$(tshark -r "$PCAP_DIR/module-11-advanced-tcp.pcap" -Y "tcp" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam TCP paketi: ${tcp_packets_m11:-N/A}"
        keepalive_packets=$(tshark -r "$PCAP_DIR/module-11-advanced-tcp.pcap" -Y "tcp.analysis.keep_alive" 2>/dev/null | wc -l | tr -d ' ')
        echo "Keep-Alive paketi: ${keepalive_packets:-N/A}"
        window_update=$(tshark -r "$PCAP_DIR/module-11-advanced-tcp.pcap" -Y "tcp.analysis.ack_rtt > 0.1" 2>/dev/null | wc -l | tr -d ' ')
        echo "Yüksek RTT (>100ms) paket: ${window_update:-N/A}"
        tcp_streams_m11=$(tshark -r "$PCAP_DIR/module-11-advanced-tcp.pcap" -T fields -e tcp.stream 2>/dev/null | sort -u | wc -l | tr -d ' ')
        echo "TCP akış sayısı: ${tcp_streams_m11:-N/A}"
        echo ""
    else
        echo "--- Modül 11: İleri TCP Analizi ---"
        echo "UYARI: module-11-advanced-tcp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 12: DNS ---
    if [[ -f "$PCAP_DIR/module-12-dns.pcap" ]]; then
        echo "--- Modül 12: DNS ---"
        dns_queries=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.flags.response == 0" 2>/dev/null | wc -l | tr -d ' ')
        echo "DNS sorgu sayısı: ${dns_queries:-N/A}"
        dns_responses=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.flags.response == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "DNS yanıt sayısı: ${dns_responses:-N/A}"
        nxdomain=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.flags.rcode == 3" 2>/dev/null | wc -l | tr -d ' ')
        echo "NXDOMAIN (hata) sayısı: ${nxdomain:-N/A}"
        noerror=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.flags.response == 1 && dns.flags.rcode == 0" 2>/dev/null | wc -l | tr -d ' ')
        echo "NOERROR (başarılı) sayısı: ${noerror:-N/A}"
        long_queries=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.qry.name.len > 30" 2>/dev/null | wc -l | tr -d ' ')
        echo "Uzun domain sorgusu (>30 karakter, tunneling): ${long_queries:-N/A}"
        dns_domains=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "Sorgulanan domain'ler: ${dns_domains:-N/A}"
        dns_a_records=$(tshark -r "$PCAP_DIR/module-12-dns.pcap" -Y "dns.a" -T fields -e dns.a 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "DNS A kaydı IP'leri: ${dns_a_records:-N/A}"
        echo ""
    else
        echo "--- Modül 12: DNS ---"
        echo "UYARI: module-12-dns.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 13: HTTP ---
    if [[ -f "$PCAP_DIR/module-13-http.pcap" ]]; then
        echo "--- Modül 13: HTTP ---"
        http_requests=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y "http.request" 2>/dev/null | wc -l | tr -d ' ')
        echo "HTTP istek sayısı: ${http_requests:-N/A}"
        http_responses=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y "http.response" 2>/dev/null | wc -l | tr -d ' ')
        echo "HTTP yanıt sayısı: ${http_responses:-N/A}"
        large_content_length=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y 'http.response.code == 200 && http.content_length > 0' -T fields -e http.content_length 2>/dev/null | sort -rn | head -1 || true)
        echo "/large yanıt gövde boyutu: ${large_content_length:-N/A}"
        server_header=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y "http.response" -T fields -e http.server -c 1 2>/dev/null | tr -d ' ')
        echo "Server header: ${server_header:-N/A}"
        sqli_count=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y 'http.request.uri contains "UNION" or http.request.uri contains "SELECT" or http.request.uri contains "%27"' 2>/dev/null | wc -l | tr -d ' ')
        echo "SQL injection denemesi: ${sqli_count:-N/A}"
        xss_count=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y 'http.request.uri contains "<script>" or http.request.uri contains "javascript:"' 2>/dev/null | wc -l | tr -d ' ')
        echo "XSS denemesi: ${xss_count:-N/A}"
        http_methods=$(tshark -r "$PCAP_DIR/module-13-http.pcap" -Y "http.request" -T fields -e http.request.method 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "HTTP metodları: ${http_methods:-N/A}"
        echo ""
    else
        echo "--- Modül 13: HTTP ---"
        echo "UYARI: module-13-http.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 14: FTP ---
    if [[ -f "$PCAP_DIR/module-14-ftp.pcap" ]]; then
        echo "--- Modül 14: FTP ---"
        ftp_packets=$(tshark -r "$PCAP_DIR/module-14-ftp.pcap" -Y "ftp" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam FTP paketi: ${ftp_packets:-N/A}"
        pasv_ports=$(tshark -r "$PCAP_DIR/module-14-ftp.pcap" -Y "ftp.response.code == 227" -T fields -e ftp.passive_port 2>/dev/null | grep -v '^$' || true)
        echo "PASV port numaraları: ${pasv_ports:-N/A}"
        ftp_username=$(tshark -r "$PCAP_DIR/module-14-ftp.pcap" -Y "ftp.request.command == USER" -T fields -e ftp.request.arg 2>/dev/null | head -1)
        echo "FTP kullanıcı adı: ${ftp_username:-N/A}"
        ftp_commands=$(tshark -r "$PCAP_DIR/module-14-ftp.pcap" -Y "ftp.request" -T fields -e ftp.request.command 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "FTP komutları: ${ftp_commands:-N/A}"
        echo ""
    else
        echo "--- Modül 14: FTP ---"
        echo "UYARI: module-14-ftp.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 15: Email (SMTP/POP3/IMAP) ---
    if [[ -f "$PCAP_DIR/module-15-email.pcap" ]]; then
        echo "--- Modül 15: Email (SMTP/POP3/IMAP) ---"
        smtp_packets=$(tshark -r "$PCAP_DIR/module-15-email.pcap" -Y "smtp" 2>/dev/null | wc -l | tr -d ' ')
        echo "SMTP paketi: ${smtp_packets:-N/A}"
        pop3_packets=$(tshark -r "$PCAP_DIR/module-15-email.pcap" -Y "pop" 2>/dev/null | wc -l | tr -d ' ')
        echo "POP3 paketi: ${pop3_packets:-N/A}"
        imap_packets=$(tshark -r "$PCAP_DIR/module-15-email.pcap" -Y "imap" 2>/dev/null | wc -l | tr -d ' ')
        echo "IMAP paketi: ${imap_packets:-N/A}"
        email_from=$(tshark -r "$PCAP_DIR/module-15-email.pcap" -Y "smtp.req.command == MAIL" -T fields -e smtp.req.parameter 2>/dev/null | head -1 || true)
        echo "Gönderen (MAIL FROM): ${email_from:-N/A}"
        email_to=$(tshark -r "$PCAP_DIR/module-15-email.pcap" -Y "smtp.req.command == RCPT" -T fields -e smtp.req.parameter 2>/dev/null | head -1 || true)
        echo "Alıcı (RCPT TO): ${email_to:-N/A}"
        email_subject=$(tshark -r "$PCAP_DIR/module-15-email.pcap" -Y 'smtp contains "Subject:"' -T fields -e text 2>/dev/null | grep -o 'Subject: [^\r\n]*' | head -1 || true)
        echo "Email konusu: ${email_subject:-N/A}"
        echo ""
    else
        echo "--- Modül 15: Email (SMTP/POP3/IMAP) ---"
        echo "UYARI: module-15-email.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 16: TLS ---
    if [[ -f "$PCAP_DIR/module-16-tls.pcap" ]]; then
        echo "--- Modül 16: TLS ---"
        tls_packets=$(tshark -r "$PCAP_DIR/module-16-tls.pcap" -Y "tls" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam TLS paketi: ${tls_packets:-N/A}"
        cipher_selected=$(tshark -r "$PCAP_DIR/module-16-tls.pcap" -Y "tls.handshake.type == 2" -T fields -e tls.cipher 2>/dev/null | grep -v '^$' | head -1 || true)
        echo "Seçilen cipher suite: ${cipher_selected:-N/A}"
        tls_version=$(tshark -r "$PCAP_DIR/module-16-tls.pcap" -Y "tls.handshake.type == 2" -T fields -e tls.handshake.version 2>/dev/null | head -1)
        echo "TLS versiyonu: ${tls_version:-N/A}"
        client_hello_count=$(tshark -r "$PCAP_DIR/module-16-tls.pcap" -Y "tls.handshake.type == 1" 2>/dev/null | wc -l | tr -d ' ')
        echo "ClientHello sayısı: ${client_hello_count:-N/A}"
        keyexchange_count=$(tshark -r "$PCAP_DIR/module-16-tls.pcap" -Y "tls.handshake.type == 12" 2>/dev/null | wc -l | tr -d ' ')
        echo "KeyExchange sayısı: ${keyexchange_count:-N/A}"
        app_data=$(tshark -r "$PCAP_DIR/module-16-tls.pcap" -Y "tls.app_data" 2>/dev/null | wc -l | tr -d ' ')
        echo "TLS Application Data paketi: ${app_data:-N/A}"
        echo ""
    else
        echo "--- Modül 16: TLS ---"
        echo "UYARI: module-16-tls.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 19: TCP Grafikleri ---
    if [[ -f "$PCAP_DIR/module-19-tcp-graph.pcap" ]]; then
        echo "--- Modül 19: TCP Grafikleri ---"
        total_pkts_m19=$(capinfos -c "$PCAP_DIR/module-19-tcp-graph.pcap" 2>/dev/null | grep -i "packets" | awk '{print $NF}' | tr -d ' ')
        echo "Toplam paket: ${total_pkts_m19:-N/A}"
        tcp_pkts_m19=$(tshark -r "$PCAP_DIR/module-19-tcp-graph.pcap" -Y "tcp" 2>/dev/null | wc -l | tr -d ' ')
        echo "TCP paketi: ${tcp_pkts_m19:-N/A}"
        http_pkts_m19=$(tshark -r "$PCAP_DIR/module-19-tcp-graph.pcap" -Y "http" 2>/dev/null | wc -l | tr -d ' ')
        echo "HTTP paketi: ${http_pkts_m19:-N/A}"
        data_bytes_m19=$(tshark -r "$PCAP_DIR/module-19-tcp-graph.pcap" -Y "tcp.len > 0" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}' || echo "N/A")
        echo "TCP veri baytı: ${data_bytes_m19:-N/A}"
        echo ""
    else
        echo "--- Modül 19: TCP Grafikleri ---"
        echo "UYARI: module-19-tcp-graph.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 20: Performans Analizi ---
    if [[ -f "$PCAP_DIR/module-20-performance.pcap" ]]; then
        echo "--- Modül 20: Performans Analizi ---"
        total_pkts_m20=$(capinfos -c "$PCAP_DIR/module-20-performance.pcap" 2>/dev/null | grep -i "packets" | awk '{print $NF}' | tr -d ' ')
        echo "Toplam paket: ${total_pkts_m20:-N/A}"
        retrans_m20=$(tshark -r "$PCAP_DIR/module-20-performance.pcap" -Y "tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')
        echo "Retransmission: ${retrans_m20:-N/A}"
        avg_rtt_m20=$(tshark -r "$PCAP_DIR/module-20-performance.pcap" -Y "tcp.analysis.ack_rtt" -T fields -e tcp.analysis.ack_rtt 2>/dev/null | grep -v '^$' | awk '{sum+=$1; count++} END {if(count>0) printf "%.6f", sum/count; else print "N/A"}')
        echo "Ortalama ACK RTT: ${avg_rtt_m20:-N/A} saniye"
        zero_win_m20=$(tshark -r "$PCAP_DIR/module-20-performance.pcap" -Y "tcp.analysis.zero_window" 2>/dev/null | wc -l | tr -d ' ')
        echo "Zero Window: ${zero_win_m20:-N/A}"
        expert_notes=$(tshark -r "$PCAP_DIR/module-20-performance.pcap" -Y "tcp.analysis" -T fields -e _ws.expert.message 2>/dev/null | sort -u | tr '\n' '|' | head -c 200 || true)
        echo "Uzman notları: ${expert_notes:-N/A}"
        echo ""
    else
        echo "--- Modül 20: Performans Analizi ---"
        echo "UYARI: module-20-performance.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 21: WLAN (802.11) ---
    if [[ -f "$PCAP_DIR/module-21-wlan.pcap" ]]; then
        echo "--- Modül 21: WLAN (802.11) ---"
        mgmt_frames=$(tshark -r "$PCAP_DIR/module-21-wlan.pcap" -Y "wlan.fc.type == 0" 2>/dev/null | wc -l | tr -d ' ')
        echo "Yönetim çerçevesi (Mgmt): ${mgmt_frames:-N/A}"
        beacon_frames=$(tshark -r "$PCAP_DIR/module-21-wlan.pcap" -Y "wlan.fc.type_subtype == 8" 2>/dev/null | wc -l | tr -d ' ')
        echo "Beacon çerçevesi: ${beacon_frames:-N/A}"
        auth_frames=$(tshark -r "$PCAP_DIR/module-21-wlan.pcap" -Y "wlan.fc.type_subtype == 11" 2>/dev/null | wc -l | tr -d ' ')
        echo "Authentication: ${auth_frames:-N/A}"
        deauth_frames=$(tshark -r "$PCAP_DIR/module-21-wlan.pcap" -Y "wlan.fc.type_subtype == 12" 2>/dev/null | wc -l | tr -d ' ')
        echo "Deauthentication: ${deauth_frames:-N/A}"
        probe_req=$(tshark -r "$PCAP_DIR/module-21-wlan.pcap" -Y "wlan.fc.type_subtype == 4" 2>/dev/null | wc -l | tr -d ' ')
        echo "Probe Request: ${probe_req:-N/A}"
        echo ""
    else
        echo "--- Modül 21: WLAN (802.11) ---"
        echo "UYARI: module-21-wlan.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 22: VoIP ---
    if [[ -f "$PCAP_DIR/module-22-voip.pcap" ]]; then
        echo "--- Modül 22: VoIP ---"
        sip_packets=$(tshark -r "$PCAP_DIR/module-22-voip.pcap" -Y "sip" 2>/dev/null | wc -l | tr -d ' ')
        echo "SIP paketi: ${sip_packets:-N/A}"
        rtp_packets=$(tshark -r "$PCAP_DIR/module-22-voip.pcap" -Y "rtp" 2>/dev/null | wc -l | tr -d ' ')
        echo "RTP paketi: ${rtp_packets:-N/A}"
        sip_methods=$(tshark -r "$PCAP_DIR/module-22-voip.pcap" -Y "sip" -T fields -e sip.Method 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        echo "SIP metodları: ${sip_methods:-N/A}"
        echo ""
    else
        echo "--- Modül 22: VoIP ---"
        echo "UYARI: module-22-voip.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 23: Baseline Analizi ---
    if [[ -f "$PCAP_DIR/module-23-baseline.pcap" ]]; then
        echo "--- Modül 23: Baseline Analizi ---"
        total_pkts_m23=$(capinfos -c "$PCAP_DIR/module-23-baseline.pcap" 2>/dev/null | grep -i "packets" | awk '{print $NF}' | tr -d ' ')
        echo "Toplam paket: ${total_pkts_m23:-N/A}"
        proto_count_m23=$(tshark -r "$PCAP_DIR/module-23-baseline.pcap" -T fields -e frame.protocols 2>/dev/null | tr ':' '\n' | sort -u | wc -l | tr -d ' ')
        echo "Protokol çeşidi: ${proto_count_m23:-N/A}"
        http_pkts_m23=$(tshark -r "$PCAP_DIR/module-23-baseline.pcap" -Y "http" 2>/dev/null | wc -l | tr -d ' ')
        echo "HTTP paketi: ${http_pkts_m23:-N/A}"
        dns_pkts_m23=$(tshark -r "$PCAP_DIR/module-23-baseline.pcap" -Y "dns" 2>/dev/null | wc -l | tr -d ' ')
        echo "DNS paketi: ${dns_pkts_m23:-N/A}"
        icmp_pkts_m23=$(tshark -r "$PCAP_DIR/module-23-baseline.pcap" -Y "icmp" 2>/dev/null | wc -l | tr -d ' ')
        echo "ICMP paketi: ${icmp_pkts_m23:-N/A}"
        syn_scan_m23=$(tshark -r "$PCAP_DIR/module-23-baseline.pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" 2>/dev/null | wc -l | tr -d ' ')
        echo "SYN scan paketi (anomali): ${syn_scan_m23:-N/A}"
        echo ""
    else
        echo "--- Modül 23: Baseline Analizi ---"
        echo "UYARI: module-23-baseline.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 24: Sınav Pratiği ---
    if [[ -f "$PCAP_DIR/module-24-exam-practice.pcap" ]]; then
        echo "--- Modül 24: Sınav Pratiği ---"
        total_packets_m24=$(capinfos -c "$PCAP_DIR/module-24-exam-practice.pcap" 2>/dev/null | grep -i "packets" | awk '{print $NF}' | tr -d ' ')
        echo "Toplam paket sayısı: ${total_packets_m24:-N/A}"
        syn_attacker_count=$(tshark -r "$PCAP_DIR/module-24-exam-practice.pcap" -Y "ip.src==172.50.2.200 && tcp.flags.syn==1 && tcp.flags.ack==0" 2>/dev/null | wc -l | tr -d ' ')
        echo "Saldırgan SYN paket sayısı: ${syn_attacker_count:-N/A}"
        http_creds=$(tshark -r "$PCAP_DIR/module-24-exam-practice.pcap" -Y 'http.request.method == POST && http contains "pass"' -T fields -e http.file_data 2>/dev/null | head -1 | tr -d ' ' || true)
        echo "HTTP POST credential: ${http_creds:-N/A}"
        dns_queries_24=$(tshark -r "$PCAP_DIR/module-24-exam-practice.pcap" -Y "dns.flags.response == 0" 2>/dev/null | wc -l | tr -d ' ')
        echo "DNS sorgu sayısı: ${dns_queries_24:-N/A}"
        ftp_pass_24=$(tshark -r "$PCAP_DIR/module-24-exam-practice.pcap" -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg 2>/dev/null | head -1 || true)
        echo "FTP şifresi: ${ftp_pass_24:-N/A}"
        echo ""
    else
        echo "--- Modül 24: Sınav Pratiği ---"
        echo "UYARI: module-24-exam-practice.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    # --- Modül 25: Forensics ---
    if [[ -f "$PCAP_DIR/module-25-forensics.pcap" ]]; then
        echo "--- Modül 25: Forensics ---"
        total_packets_m25=$(capinfos -c "$PCAP_DIR/module-25-forensics.pcap" 2>/dev/null | grep -i "packets" | awk '{print $NF}' | tr -d ' ')
        echo "Toplam paket sayısı: ${total_packets_m25:-N/A}"
        syn_flood_count=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y "ip.src==172.50.2.200 && tcp.flags.syn==1" 2>/dev/null | wc -l | tr -d ' ')
        echo "Toplam SYN flood paketleri: ${syn_flood_count:-N/A}"
        dns_exfil=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y "dns.qry.name.len > 30" 2>/dev/null | wc -l | tr -d ' ')
        echo "DNS exfiltration sorgusu: ${dns_exfil:-N/A}"
        sql_injection=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y 'http.request.uri contains "UNION" or http.request.uri contains "SELECT"' 2>/dev/null | wc -l | tr -d ' ')
        echo "SQL injection denemesi: ${sql_injection:-N/A}"
        xss_attempts=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y 'http.request.uri contains "<script>"' 2>/dev/null | wc -l | tr -d ' ')
        echo "XSS denemesi: ${xss_attempts:-N/A}"
        ftp_pass_25=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg 2>/dev/null | head -1 || true)
        echo "FTP brute force şifre: ${ftp_pass_25:-N/A}"
        ftp_failed=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y "ftp.response.code == 530" 2>/dev/null | wc -l | tr -d ' ')
        echo "FTP başarısız giriş: ${ftp_failed:-N/A}"
        ftp_success=$(tshark -r "$PCAP_DIR/module-25-forensics.pcap" -Y "ftp.response.code == 230" 2>/dev/null | wc -l | tr -d ' ')
        echo "FTP başarılı giriş: ${ftp_success:-N/A}"
        echo ""
    else
        echo "--- Modül 25: Forensics ---"
        echo "UYARI: module-25-forensics.pcap bulunamadı, atlanıyor."
        echo ""
    fi

    echo "=== Cevap Anahtarı Sonu ==="
} > "$OUTPUT"

echo "Cevap anahtarı: shared/pcaps/answer-key.txt"
