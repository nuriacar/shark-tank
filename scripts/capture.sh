#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

CAPTURE_NAME="${1:-capture}"
PCAP_FILE="/pcaps/${CAPTURE_NAME}.pcap"
LOCAL_FILE="${PROJECT_DIR}/shared/pcaps/${CAPTURE_NAME}.pcap"

if [ "${1:-}" = "--stop" ]; then
    echo "Capture durduruluyor..."
    docker exec shark-tank-client pkill tcpdump 2>/dev/null || true
    sleep 1
    echo "Pcap dosyası: ${LOCAL_FILE}"
    echo "Wireshark ile açın: wireshark ${LOCAL_FILE}"
    exit 0
fi

if [ -z "${1:-}" ]; then
    echo "Kullanım: $0 <capture-adı> [--stop]"
    echo ""
    echo "Örnekler:"
    echo "  $0 http-basic        # Capture başlat"
    echo "  $0 --stop            # Capture durdur"
    echo ""
    echo "Mevcut pcap dosyaları:"
    ls -la "${PROJECT_DIR}"/shared/pcaps/*.pcap 2>/dev/null || echo "  (boş)"
    exit 1
fi

echo "=== Capture başlatılıyor: ${CAPTURE_NAME} ==="
echo "Pcap dosyası: ${PCAP_FILE}"
echo "Client container (shark-tank-client) üzerinde tcpdump başlatılıyor..."
echo ""
echo "Capture'i durdurmak için: $0 --stop"
echo ""

docker exec shark-tank-client tcpdump -i eth0 -w "${PCAP_FILE}" -v 2>&1
