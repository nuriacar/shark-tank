#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [ "${1:-}" != "-y" ] && [ "${1:-}" != "--yes" ]; then
    echo "=== Shark-Tank Lab Temizlik ==="
    echo ""
    echo "UYARI: Bu işlem aşağıdakileri silecek:"
    echo "  - Tüm container'lar ve volumes"
    echo "  - Local Docker images"
    echo "  - Tüm pcap dosyaları (shared/pcaps/)"
    echo "  - SSL sertifikaları (shared/certs/)"
    echo ""
    read -p "Devam etmek istiyor musunuz? [y/N] " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "İptal edildi."
        exit 0
    fi
fi

echo ""
echo "[1/3] Container'lar durduruluyor..."
docker compose down 2>/dev/null || true

echo "[2/3] Volumes ve local images siliniyor..."
docker compose down -v --rmi local 2>/dev/null || true

echo "[3/3] Dosyalar temizleniyor..."
rm -f shared/pcaps/*.pcap
rm -f shared/certs/*.key shared/certs/*.crt

echo ""
echo "Temizlendi. Yeniden başlatmak için: make setup"
