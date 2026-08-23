#!/bin/bash
# Shark-Tank regresyon testi: bilinen pcap'lerde BEKLENEN anahtar bulguların
# raporda geçtiğini doğrular. Syntax kırılırsa / bayat rapor kalırsa anında FAIL.
# Kullanım: ./scripts/shark-tank-test.sh   (veya: make test-sharktank)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PCAP_DIR="$PROJECT_DIR/shared/pcaps"
ST="$SCRIPT_DIR/shark-tank.sh"

PASS=0; FAIL=0

expect() {
    local pcap_md="$1"; shift
    local desc="$1"; shift
    if [ ! -s "$pcap_md" ]; then
        echo "  [FAIL] $desc — rapor yok: $pcap_md"
        FAIL=$((FAIL+1)); return
    fi
    local ok=1
    for needle in "$@"; do
        if ! grep -qF "$needle" "$pcap_md"; then
            echo "  [FAIL] $desc — eksik: '$needle'"
            ok=0
        fi
    done
    if [ "$ok" -eq 1 ]; then
        echo "  [OK]   $desc"
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
}

echo "=== Shark-Tank Regresyon Testi ==="
echo ""

# 1) Raporları yeniden üret (bayat-rapor tuzağına karşı)
"$ST" "$PCAP_DIR" > /dev/null 2>&1

# 2) Beklenen bulgular (lab gerçekleriyle birebir)
expect "$PCAP_DIR/module-03-arp.md"         "m03 ARP sweep"          "ARP Host Keşfi"
expect "$PCAP_DIR/module-05-icmp.md"        "m05 ICMP redirect+tünel" "ICMP Redirect" "ICMP Tüneli" "7354"
expect "$PCAP_DIR/module-06-fragmentation.md" "m06 overlap"          "Fragment Overlap"
expect "$PCAP_DIR/module-13-http.md"        "m13 Basic auth+chunked" "Basic auth" "chunked"
expect "$PCAP_DIR/module-16-tls.md"         "m16 OCSP good"           "OCSP" "good"
expect "$PCAP_DIR/module-17-kerberos.md"    "m17 Kerberoasting+RC4"   "Kerberoasting" "RC4"
expect "$PCAP_DIR/module-19-smb2.md"        "m19 svcctl+dosya envanteri" "svcctl" "veritabani.bin" "96000"
expect "$PCAP_DIR/module-28-forensics.md"   "m28 exfil entropy+kill-chain" "entropi" "Kill Chain" "IOC"
expect "$PCAP_DIR/module-27-exam-practice.md" "m27 ZIP+beacon"       "ZIP" "beacon"

# 3) JSON geçerliliği (m28)
if python3 -m json.tool "$PCAP_DIR/module-28-forensics.json" > /dev/null 2>&1; then
    echo "  [OK]   JSON çıktısı geçerli (m28)"
    PASS=$((PASS+1))
else
    echo "  [FAIL] JSON bozuk: $PCAP_DIR/module-28-forensics.json"
    FAIL=$((FAIL+1))
fi

# 4) Kampanya raporu üretildi mi (>=2 pcap)
if [ -s "$PCAP_DIR/campaign.md" ]; then
    echo "  [OK]   campaign.md üretildi"
    PASS=$((PASS+1))
else
    echo "  [FAIL] campaign.md yok"
    FAIL=$((FAIL+1))
fi

# 5) Dış pcap: bilinmeyen dosyada çalışma (geçici, ARP'suz sessiz dosya)
TMPPCAP=$(mktemp -u /tmp/st-test-XXXX).pcap
cp "$PCAP_DIR/module-01-basics.pcap" "$TMPPCAP"
"$ST" "$TMPPCAP" > /dev/null 2>&1
if [ -s "${TMPPCAP%.pcap}.md" ]; then
    echo "  [OK]   yabancı pcap'te rapor üretildi"
    PASS=$((PASS+1)); rm -f "$TMPPCAP" "${TMPPCAP%.pcap}.md" "${TMPPCAP%.pcap}.json"
else
    echo "  [FAIL] yabancı pcap testi"
    FAIL=$((FAIL+1)); rm -f "$TMPPCAP"
fi

echo ""
echo "=== Sonuç: $PASS geçti, $FAIL başarısız ==="
[ "$FAIL" -eq 0 ] && echo "SHARK-TANK REGRESYON: TAMAM" || exit 1
