#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Shark-Tank Network Lab Setup ==="

echo "[1/3] SSL sertifikaları kontrol ediliyor..."
mkdir -p shared/certs shared/pcaps
if [ ! -f shared/certs/server.crt ]; then
    echo "  Sertifika oluşturuluyor..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout shared/certs/server.key \
        -out shared/certs/server.crt \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Shark-Tank/OU=Network Analysis Lab/CN=secure.shark-tank.local"
    echo "  Sertifika oluşturuldu."
else
    echo "  Sertifika mevcut, atlanıyor."
fi

echo "[2/3] Docker image'lar build ediliyor..."
docker compose build 2>&1 | tail -3

echo "[3/3] Container'lar başlatılıyor..."
docker compose up -d

echo ""
echo "Container'larin hazır olması bekleniyor..."
sleep 5

echo ""
echo "=== Container Durumlari ==="
docker compose ps

echo ""
echo "=== Ağ Bilgileri ==="
docker network inspect shark-tank --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}' 2>/dev/null || docker network ls | grep shark-tank || echo "Ağ bilgisi için: docker network ls"

echo ""
echo "=== IP Adresleri ==="
echo "  Web (HTTP):    172.50.2.10"
echo "  DNS:           172.50.2.11"
echo "  TCP Echo:      172.50.2.12:8080"
echo "  HTTPS:         172.50.2.13:443"
echo "  ICMP Target:   172.50.2.14"
echo "  FTP:           172.50.2.15:21"
echo "  SMTP:          172.50.2.16:1025"
echo "  UDP Echo:      172.50.2.17:9090/udp"
echo "  IMAP/POP3:     172.50.2.18:110/143/587"
echo "  VoIP (SIP):    172.50.2.22:5060/udp"
echo "  DHCP Server:   172.50.9.2"
echo "  Client:        172.50.2.100"
echo "  Attacker:      172.50.2.200"
echo ""
echo "=== Hazır! ==="
echo "Modül rehberlerini incelemek için module-XX/module-XX.md dosyalarını okuyun."
echo "Trafik üretmek için: scripts/generate-traffic.sh <modül-adı>"
echo "Capture başlatmak için: scripts/capture.sh <dosya-adı>"
