#!/bin/bash
# Repo modül md'lerini blog _posts dosyalarına senkronlar (front matter korunur).
set -euo pipefail

SHARK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BLOG_DIR="${1:-$SHARK_DIR/../nuriacar.github.io}"

if [ ! -d "$BLOG_DIR/_posts" ]; then
    echo "Blog dizini bulunamadi: $BLOG_DIR"
    exit 1
fi

SYNCED=0
for module_dir in "$SHARK_DIR"/module-*/; do
    name="$(basename "$module_dir")"                      # module-13-http
    md="$module_dir/$name.md"
    [ -f "$md" ] || continue

    # module-13-http -> m13
    num="$(echo "$name" | sed -E 's/module-([0-9]+)-.*/\1/')"
    short="$(echo "$name" | sed -E 's/^module-[0-9]+-//')"  # http

    post="$(ls "$BLOG_DIR/_posts/"*"-m${num}-${short}.md" 2>/dev/null | head -1 || true)"
    if [ -z "$post" ]; then
        echo "  [ATLANDI] $name icin blog post yok"
        continue
    fi

    # Front matter (--- ... ---) koru, govdeyi module md ile degistir
    awk 'NR==1 && $0=="---"{fm=1;print;next} fm && $0=="---"{print;exit} fm{print;next} {exit}' "$post" > /tmp/post-fm.txt
    if [ "$(wc -l < /tmp/post-fm.txt)" -lt 3 ]; then
        echo "  [HATA] $post front matter bozuk, atlandi"
        continue
    fi
    cat /tmp/post-fm.txt "$md" > /tmp/post-new.txt
    # blogda modul-ici "tıkla" footer baglantisi zaten var; birebir kopya yeterli
    cp /tmp/post-new.txt "$post"
    SYNCED=$((SYNCED+1))
    echo "  [OK] $(basename "$post")"
done

echo ""
echo "Senkronize edildi: $SYNCED post"
