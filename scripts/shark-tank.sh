#!/bin/bash
# Shark-Tank analiz koşucusu: tek pcap veya dizin tarar, her pcap yanına .md raporu yazar.
# Dizin modunda ayrıca kampanya görünümü (pcap'ler arası ortak IOC) üretir.
# Kullanım:
#   ./scripts/shark-tank.sh <pcap-dosyasi>
#   ./scripts/shark-tank.sh <dizin>          # dizindeki tüm pcap/pcapng + campaign.md
#   ./scripts/shark-tank.sh                  # varsayılan: shared/pcaps
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LUA="$PROJECT_DIR/shared/shark-tank.lua"

TSHARK="${TSHARK:-tshark}"
command -v "$TSHARK" >/dev/null 2>&1 || TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
command -v "$TSHARK" >/dev/null 2>&1 || { echo "HATA: tshark bulunamadı"; exit 1; }
[ -f "$LUA" ] || { echo "HATA: $LUA yok"; exit 1; }

TARGET="${1:-$PROJECT_DIR/shared/pcaps}"
OK=0; FAIL=0; DIR_MODE=0

analyze_one() {
    local pcap="$1"
    local out="${pcap%.*}.md"
    rm -f "$out" "$pcap.json"   # bayat rapor koruması: önce sil (script kırılırsa FAIL görünür)
    SHARK_TANK_PCAP="$pcap" SHARK_TANK_QUIET=1 SHARK_TANK_JSON=1 \
        "$TSHARK" -q -X "lua_script:$LUA" -r "$pcap" 2>/dev/null
    if [ -s "$out" ]; then
        echo "[OK] $out"
        OK=$((OK+1))
    else
        echo "[FAIL] $pcap"
        FAIL=$((FAIL+1))
    fi
}

# Kampanya görünümü: pcap başına JSON'lardan ortak IOC'leri çıkar
campaign_report() {
    local dir="$1"
    python3 - "$dir" <<'PYEOF'
import json, os, sys, glob

d = sys.argv[1]
rows = {}
for j in sorted(glob.glob(os.path.join(d, "*.json"))):
    try:
        rows[os.path.basename(j)] = json.load(open(j))
    except Exception:
        pass
if len(rows) < 2:
    sys.exit(0)

def norm_list(v):
    if isinstance(v, list):
        return {str(x) for x in v}
    return set()

def collect(key):
    out = {}
    for name, r in rows.items():
        vals = norm_list(r.get("iocs", {}).get(key))
        if vals:
            out[name] = vals
    return out

lines = []
lines.append("# Shark-Tank Kampanya Görünümü — %s" % d)
lines.append("")
lines.append("%d pcap raporu tarandı; AYNI göstergenin birden fazla dosyada görünmesi" % len(rows))
lines.append("tek olay ötesi (aynı saldırgan/altyapı) bağlantısı kurar.")
lines.append("")

pairs = [
    ("scan_sources", "Tarama kaynakları (IP)"),
    ("c2_channels", "C2 kanalları"),
    ("icmp_tunnel_idents", "ICMP tünel identifier'ları"),
    ("ntlm_accounts", "NTLM hesapları"),
    ("fake_user_agents", "Sahte User-Agent"),
    ("smb_badname_trees", "Harici SMB hedefleri"),
    ("leaked_credentials", "Sızan kimlik bilgileri"),
]
found_any = False
for key, title in pairs:
    per = collect(key)
    if len(per) < 2:
        continue
    # ikili örtüşme ara
    names = sorted(per)
    overlaps = []
    for i in range(len(names)):
        for k in range(i + 1, len(names)):
            common = per[names[i]] & per[names[k]]
            if common:
                overlaps.append((names[i], names[k], common))
    if not overlaps:
        continue
    found_any = True
    lines.append("## %s" % title)
    lines.append("")
    for a, b, common in overlaps:
        lines.append("- **%s ↔ %s**: ortak %d değer" % (a, b, len(common)))
        for c in sorted(common)[:4]:
            lines.append("  - `%s`" % c)
    lines.append("")

if not found_any:
    lines.append("Pcap'ler arasında ortak IOC bulunamadı (bağımsız olaylar).")

out = os.path.join(d, "campaign.md")
open(out, "w").write("\n".join(lines) + "\n")
print("[OK] %s" % out)
PYEOF
}

if [ -d "$TARGET" ]; then
    DIR_MODE=1
    for f in "$TARGET"/*.pcap "$TARGET"/*.pcapng; do
        [ -f "$f" ] || continue
        analyze_one "$f"
    done
    if [ "$OK" -ge 2 ]; then
        campaign_report "$TARGET"
    fi
elif [ -f "$TARGET" ]; then
    analyze_one "$TARGET"
else
    echo "HATA: $TARGET bulunamadı"
    exit 1
fi

echo ""
echo "Bitti: $OK rapor üretildi, $FAIL hata"
[ "$FAIL" -eq 0 ]
