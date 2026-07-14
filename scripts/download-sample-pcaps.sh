#!/bin/bash
# Shark-Tank: Download Wireshark sample captures for modules that can't
# generate their own traffic (e.g., WLAN 802.11 management frames).
set -euo pipefail

BASE_URL="https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures"
PCAP_DIR="$(cd "$(dirname "$0")/../shared/pcaps" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

download_gz() {
    local filename="$1"
    local label="$2"
    local url="${BASE_URL}/${filename}"
    local dest="${PCAP_DIR}/${label}"
    local tmpfile="${dest}.tmp.gz"
    if [ -f "$dest" ]; then
        echo "  Zaten var: $label"
        return 0
    fi
    echo "  Indiriliyor: $label..."
    if curl -sL -o "$tmpfile" "$url"; then
        if gunzip -c "$tmpfile" > "$dest" 2>/dev/null; then
            echo "  Indirildi: $label"
            rm -f "$tmpfile"
        else
            mv "$tmpfile" "$dest"
            echo "  Indirildi (raw): $label"
        fi
    else
        echo "  HATA: Indirme basarisiz: $url"
        rm -f "$tmpfile" 2>/dev/null || true
        return 1
    fi
}

echo "=== Shark-Tank: Sample Pcap Indirici ==="
echo ""

echo "[WLAN 802.11]"
download_gz "wpa-eap-tls.pcap.gz" "module-21-wlan-raw.pcap"

# Generate management frames and merge with real capture
RAW="${PCAP_DIR}/module-21-wlan-raw.pcap"
FINAL="${PCAP_DIR}/module-21-wlan.pcap"

if [ -f "$RAW" ]; then
    if [ ! -f "$FINAL" ] || [ "$RAW" -nt "$FINAL" ]; then
        MGMT_PY="${SCRIPT_DIR}/_gen_wlan_mgmt.py"
        MGMT_PCAP="${PCAP_DIR}/module-21-wlan-mgmt.pcap"

        # Write Python generator script
        cat > "$MGMT_PY" << 'PYEOF'
import struct, sys

out = sys.argv[1]

def rt():
    return bytes([0x00, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x02, 0x6c, 0x09, 0x00, 0x00])

def dur():
    return struct.pack('<H', 0)

def mac(s):
    return bytes.fromhex(s.replace(':', ''))

def seq(n=0):
    return struct.pack('<H', n << 4)

def hdr(t, s, a1, a2, a3, sn=0):
    return bytes([(t & 3) << 2 | (s & 0xf) << 4, 0]) + dur() + mac(a1) + mac(a2) + mac(a3) + seq(sn)

ap = "00:11:22:33:44:55"
cl = "66:77:88:99:aa:bb"

ssid = bytes([0, 15]) + b"Shark-Tank-Corp"
rates = bytes([1, 8, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24])
rsn = bytes([0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
             0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
             0x00, 0x0f, 0xac, 0x02, 0x00, 0x00])

pkts = []
ts = 0

for i in range(3):
    body = struct.pack('<QH', ts * 1000000, 100) + struct.pack('<H', 0x0401)
    body += ssid + rates + bytes([3, 1, 6]) + rsn
    pkts.append((rt() + hdr(0, 8, "ff:ff:ff:ff:ff:ff", ap, ap, sn=i) + body, ts * 1000000))
    ts += 102400

pkts.append((rt() + hdr(0, 4, "ff:ff:ff:ff:ff:ff", cl, "ff:ff:ff:ff:ff:ff") + ssid + rates, ts * 1000000))
ts += 50000

body = struct.pack('<QH', ts * 1000000, 100) + struct.pack('<H', 0x0401) + ssid + rates + bytes([3, 1, 6])
pkts.append((rt() + hdr(0, 5, cl, ap, ap) + body, ts * 1000000))
ts += 30000

pkts.append((rt() + hdr(0, 11, ap, cl, ap) + struct.pack('<HH', 0, 1), ts * 1000000))
ts += 10000
pkts.append((rt() + hdr(0, 11, cl, ap, ap) + struct.pack('<HHH', 0, 2, 0), ts * 1000000))
ts += 10000

pkts.append((rt() + hdr(0, 0, ap, cl, ap) + struct.pack('<HH', 0x0401, 10) + ssid + rates, ts * 1000000))
ts += 10000
pkts.append((rt() + hdr(0, 1, cl, ap, ap) + struct.pack('<HHH', 0x0401, 0, 1), ts * 1000000))
ts += 20000

pkts.append((rt() + hdr(0, 10, cl, ap, ap) + struct.pack('<H', 3), ts * 1000000))
ts += 5000
pkts.append((rt() + hdr(0, 12, cl, ap, ap) + struct.pack('<H', 3), ts * 1000000))

with open(out, 'wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
    for d, t in pkts:
        sec = int(t // 1000000)
        usec = int(t % 1000000)
        f.write(struct.pack('<IIII', sec, usec, len(d), len(d)))
        f.write(d)

print(f"      {len(pkts)} management frames")
PYEOF

        echo "  Yonetim cerceveleri olusturuluyor..."
        python3 "$MGMT_PY" "$MGMT_PCAP"
        rm -f "$MGMT_PY"

        if [ -f "$MGMT_PCAP" ]; then
            echo "  Malformed frame'ler temizleniyor..."
            CLEAN="${PCAP_DIR}/module-21-wlan-mgmt-clean.pcap"
            tshark -r "$MGMT_PCAP" -Y "!_ws.malformed" -w "$CLEAN" 2>/dev/null
            if [ -f "$CLEAN" ]; then
                rm -f "$MGMT_PCAP"
                MGMT_PCAP="$CLEAN"
            fi
            echo "  Birlestiriliyor: mgmt + raw capture..."
            TMP="${FINAL}.tmp"
            mergecap -w "$TMP" "$MGMT_PCAP" "$RAW" 2>/dev/null
            mv "$TMP" "$FINAL"
            rm -f "$MGMT_PCAP" "$RAW"
            echo "  Birlestirildi: $FINAL"
        else
            cp "$RAW" "$FINAL"
            rm -f "$RAW"
        fi
    fi
fi

echo ""
echo "Indirilen dosyalar:"
ls -lh "${PCAP_DIR}/module-21-wlan.pcap" 2>/dev/null || echo "  (wlan pcap indirilemedi)"
