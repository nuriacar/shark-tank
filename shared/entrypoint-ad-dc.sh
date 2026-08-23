#!/bin/bash
# shark-tank AD DC — ilk açılışta provision (~15 sn), sonra samba foreground
set -euo pipefail

STATE_DIR="/var/lib/samba"
REALM="SHARK-TANK.LOCAL"
ADMIN_PASS="${AD_ADMIN_PASS:-SharkTank2026!}"
ANALYST_USER="${AD_ANALYST_USER:-analyst}"
ANALYST_PASS="${AD_ANALYST_PASS:-analyst123!}"
SVC_USER="${AD_SVC_USER:-svc-backup}"
SVC_PASS="${AD_SVC_PASS:-KerberoastMe123!}"

if [ ! -f "${STATE_DIR}/private/sam.ldb" ]; then
    echo "[AD-DC] Ilk acilis: domain provision ediliyor (${REALM})..."
    samba-tool domain provision \
        --realm="${REALM}" \
        --domain=SHARK-TANK \
        --server-role=dc \
        --dns-backend=NONE \
        --adminpass="${ADMIN_PASS}" \
        --use-rfc2307 \
        --option="posix:eadb=/var/lib/samba/xattr.tdb"

    mkdir -p /srv/shark-share
    echo "laboratuvar raporu - shark-tank m19 smb2 alistirmasi" \
        > /srv/shark-share/rapor.txt

    # Provision smb.conf'u Debian'da /etc/samba altina yazabilir
    SMBCONF="${STATE_DIR}/etc/smb.conf"
    [ -f "${SMBCONF}" ] || SMBCONF="/etc/samba/smb.conf"

    # xattr emulasyonu runtime icin de gecerli olsun (container FS kisiti)
    grep -q "posix:eadb" "${SMBCONF}" || \
        sed -i 's/^\[global\]$/[global]\n posix:eadb = \/var\/lib\/samba\/xattr.tdb/' "${SMBCONF}"

    # m18 dersi: duz metin simple bind (sifre pcap'te gorunur) ogretmek icin
    grep -q "ldap server require strong auth" "${SMBCONF}" || \
        sed -i 's/^\[global\]$/[global]\n ldap server require strong auth = no/' "${SMBCONF}"

    # m19 dersi: svcctl/dcerpc trafiği Wireshark'ta görünür kalsın (SMB3 şifreleme kapalı,
    # imzalama zorunluluğu sürer). Sınav/lab ortamı bilinçli tercihi.
    grep -q "^smb encrypt" "${SMBCONF}" || \
        sed -i 's/^\[global\]$/[global]\n smb encrypt = off/' "${SMBCONF}"

    # m17 dersi: Kerberoasting'in keskin imzası (etype 23/RC4 bilet) gerçek üretilebilsin
    grep -q "allow weak crypto" "${SMBCONF}" || \
        sed -i 's/^\[global\]$/[global]\n kerberos allow weak crypto = yes/' "${SMBCONF}"

    cat >> "${SMBCONF}" <<'EOF'

[shark-share]
    path = /srv/shark-share
    read only = no
    browseable = yes
    nt acl support = no
    force user = root
    create mask = 0666
EOF

    echo "[AD-DC] Kullanicilar olusturuluyor..."
    samba-tool user add "${ANALYST_USER}" "${ANALYST_PASS}"
    samba-tool user add "${SVC_USER}" "${SVC_PASS}"
    samba-tool spn add "backup/${SVC_USER}.shark-tank.local" "${SVC_USER}"

    # m17 dersi: svc-backup yalniz RC4 (etype 23) destekler -> Kerberoasting
    # senaryosunda saldrganin kvno -e rc4-hmac istegi gercek RC4 bilet dondurur
    cat > /tmp/et.ldif <<'LDF'
dn: CN=svc-backup,CN=Users,DC=shark-tank,DC=local
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 4
LDF
    ldbmodify -H "${STATE_DIR}/private/sam.ldb" /tmp/et.ldif >/dev/null 2>&1 || \
        ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/et.ldif >/dev/null 2>&1 || true

    # SASL kanonik ad farkliliklari icin ek SPN'ler
    samba-tool spn add "ldap/shark-tank-ad-dc.shark-tank.local" "DC$" || true
    samba-tool spn add "host/shark-tank-ad-dc.shark-tank.local" "DC$" || true
    # cyrus-sasl kanoniklestirmesi tek etiket + kisa domain uretebiliyor
    samba-tool spn add "ldap/shark-tank-ad-dc.shark-tank" "DC$" || true
    samba-tool spn add "host/shark-tank-ad-dc.shark-tank" "DC$" || true

    # Kerberoasting alistirmasi: svc hesabi yalnizca RC4 (etype 23) istesin
    SVC_DN=$(ldbsearch -H "${STATE_DIR}/private/sam.ldb" \
        "sAMAccountName=${SVC_USER}" dn 2>/dev/null | \
        grep "^dn:" | head -1 | sed 's/^dn: //')
    printf 'dn: %s\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 31\n\n' \
        "${SVC_DN}" | ldbmodify -H "${STATE_DIR}/private/sam.ldb"
    echo "[AD-DC] ${SVC_USER} zayif sifreleme acik (RC4, etype 23 alistirmasi)"
fi

echo "[AD-DC] samba baslatiliyor (foreground)..."
exec samba -i
