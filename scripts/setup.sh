#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

CREDENTIALS_FILE="${PROJECT_DIR}/shared/credentials.env"
if [ -f "${CREDENTIALS_FILE}" ]; then
    set -a
    source "${CREDENTIALS_FILE}"
    set +a
fi

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

INSTALLED_SOMETHING=0

# ─── Platform Detection ────────────────────────────────────────

detect_platform() {
    local uname_s
    uname_s="$(uname -s 2>/dev/null || echo Unknown)"

    if [ "$uname_s" = "Darwin" ]; then
        echo "macos"
    elif [ "$uname_s" = "Linux" ]; then
        if grep -qi microsoft /proc/version 2>/dev/null; then
            echo "wsl"
        elif command -v apt-get &>/dev/null; then
            echo "debian"
        elif command -v dnf &>/dev/null; then
            echo "fedora"
        elif command -v apk &>/dev/null; then
            echo "alpine"
        elif command -v pacman &>/dev/null; then
            echo "arch"
        else
            echo "linux"
        fi
    else
        echo "unsupported"
    fi
}

PLATFORM="$(detect_platform)"

# ─── Helper Functions ───────────────────────────────────────────

check_cmd() {
    command -v "$1" &>/dev/null
}

version_of() {
    local cmd="$1"
    local ver
    ver="$($cmd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)" || true
    echo "${ver:-bilinmiyor}"
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-Y}"
    local suffix
    if [ "$default" = "Y" ]; then
        suffix="[Y/n]"
    else
        suffix="[y/N]"
    fi
    echo -ne "    ${YELLOW}${prompt} ${suffix}${NC} "
    read -r answer 2>/dev/null || answer=""
    answer="${answer:-$default}"
    case "$answer" in
        [Yy]|[Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

log_ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
log_fail() { echo -e "  ${RED}✗${NC} $1"; }
log_dim()  { echo -e "  ${DIM}$1${NC}"; }

run_silent() {
    "$@" >/dev/null 2>&1
}

# ─── Prerequisite Checkers + Installers ─────────────────────────

check_bash() {
    if check_cmd bash; then
        log_ok "bash       : $(version_of bash)"
        return 0
    fi
    log_fail "bash bulunamadı (bu script bash ile çalışıyor, bir şeyler çok yanlış)"
    return 1
}

check_git() {
    if check_cmd git; then
        log_ok "git        : $(version_of git)"
        return 0
    fi
    log_warn "git bulunamadı (repo zaten klonlanmış, devam edilebilir)"
    return 0
}

check_make() {
    if check_cmd make; then
        log_ok "make       : $(version_of make)"
        return 0
    fi

    log_warn "make bulunamadı"
    if [ "$PLATFORM" = "macos" ]; then
        if ask_yes_no "Xcode Command Line Tools kurulumsun mu? (make içerir)"; then
            xcode-select --install 2>/dev/null || true
            echo -n "  Kurulum tamamlanana kadar bekleyin, sonra Enter'a basın... "
            read -r
            INSTALLED_SOMETHING=1
            if check_cmd make; then
                log_ok "make       : kuruldu ($(version_of make))"
                return 0
            fi
        fi
    elif [ "$PLATFORM" = "debian" ] || [ "$PLATFORM" = "wsl" ]; then
        if ask_yes_no "make kurulumsun mu? (sudo apt-get install -y make)"; then
            sudo apt-get update -qq && sudo apt-get install -y -qq make
            INSTALLED_SOMETHING=1
            if check_cmd make; then
                log_ok "make       : kuruldu"
                return 0
            fi
        fi
    elif [ "$PLATFORM" = "fedora" ]; then
        if ask_yes_no "make kurulumsun mu? (sudo dnf install -y make)"; then
            sudo dnf install -y -q make
            INSTALLED_SOMETHING=1
            if check_cmd make; then
                log_ok "make       : kuruldu"
                return 0
            fi
        fi
    fi

    log_dim "make olmadan devam edilebilir: ./scripts/setup.sh, ./scripts/generate-traffic.sh"
    return 0
}

check_openssl() {
    if check_cmd openssl; then
        log_ok "openssl    : $(version_of openssl)"
        return 0
    fi

    log_warn "openssl bulunamadı (SSL sertifika üretimi için gerekli)"

    if [ "$PLATFORM" = "macos" ]; then
        if ask_yes_no "Xcode Command Line Tools kurulumsun mu? (openssl içerir)"; then
            xcode-select --install 2>/dev/null || true
            echo -n "  Kurulum tamamlanana kadar bekleyin, sonra Enter'a basın... "
            read -r
            INSTALLED_SOMETHING=1
            if check_cmd openssl; then
                log_ok "openssl    : kuruldu"
                return 0
            fi
        fi
    elif [ "$PLATFORM" = "debian" ] || [ "$PLATFORM" = "wsl" ]; then
        if ask_yes_no "openssl kurulumsun mu? (sudo apt-get install -y openssl)"; then
            sudo apt-get update -qq && sudo apt-get install -y -qq openssl
            INSTALLED_SOMETHING=1
            if check_cmd openssl; then
                log_ok "openssl    : kuruldu"
                return 0
            fi
        fi
    elif [ "$PLATFORM" = "fedora" ]; then
        if ask_yes_no "openssl kurulumsun mu? (sudo dnf install -y openssl)"; then
            sudo dnf install -y -q openssl
            INSTALLED_SOMETHING=1
            if check_cmd openssl; then
                log_ok "openssl    : kuruldu"
                return 0
            fi
        fi
    elif [ "$PLATFORM" = "alpine" ]; then
        if ask_yes_no "openssl kurulumsun mu? (sudo apk add openssl)"; then
            sudo apk add openssl
            INSTALLED_SOMETHING=1
            if check_cmd openssl; then
                log_ok "openssl    : kuruldu"
                return 0
            fi
        fi
    elif [ "$PLATFORM" = "arch" ]; then
        if ask_yes_no "openssl kurulumsun mu? (sudo pacman -S --noconfirm openssl)"; then
            sudo pacman -S --noconfirm openssl
            INSTALLED_SOMETHING=1
            if check_cmd openssl; then
                log_ok "openssl    : kuruldu"
                return 0
            fi
        fi
    fi

    log_fail "openssl bulunamadı. SSL sertifika oluşturulamaz."
    log_dim "Kurulum: https://www.openssl.org/source/"
    return 1
}

check_python3() {
    if check_cmd python3; then
        log_ok "python3    : $(version_of python3)"
        return 0
    fi

    log_warn "python3 bulunamadı (forensics pcap birleştirme için gerekli)"

    if [ "$PLATFORM" = "macos" ]; then
        if check_cmd brew; then
            if ask_yes_no "python3 kurulumsun mu? (brew install python3)"; then
                brew install python3
                INSTALLED_SOMETHING=1
            fi
        else
            if ask_yes_no "Xcode Command Line Tools kurulumsun mu? (python3 içerir)"; then
                xcode-select --install 2>/dev/null || true
                echo -n "  Kurulum tamamlanana kadar bekleyin, sonra Enter'a basın... "
                read -r
                INSTALLED_SOMETHING=1
            fi
        fi
    elif [ "$PLATFORM" = "debian" ] || [ "$PLATFORM" = "wsl" ]; then
        if ask_yes_no "python3 kurulumsun mu? (sudo apt-get install -y python3)"; then
            sudo apt-get update -qq && sudo apt-get install -y -qq python3
            INSTALLED_SOMETHING=1
        fi
    elif [ "$PLATFORM" = "fedora" ]; then
        if ask_yes_no "python3 kurulumsun mu? (sudo dnf install -y python3)"; then
            sudo dnf install -y -q python3
            INSTALLED_SOMETHING=1
        fi
    elif [ "$PLATFORM" = "alpine" ]; then
        if ask_yes_no "python3 kurulumsun mu? (sudo apk add python3)"; then
            sudo apk add python3
            INSTALLED_SOMETHING=1
        fi
    elif [ "$PLATFORM" = "arch" ]; then
        if ask_yes_no "python3 kurulumsun mu? (sudo pacman -S --noconfirm python3)"; then
            sudo pacman -S --noconfirm python3
            INSTALLED_SOMETHING=1
        fi
    fi

    if check_cmd python3; then
        log_ok "python3    : kuruldu"
        return 0
    fi

    log_dim "python3 olmadan module-12 ve module-13 pcap'leri eksik olacak (geri kalan çalışır)"
    return 0
}

check_docker() {
    if ! check_cmd docker; then
        log_warn "Docker bulunamadı"

        if [ "$PLATFORM" = "macos" ]; then
            if check_cmd brew; then
                if ask_yes_no "Docker Desktop kurulumsun mu? (brew install --cask docker)"; then
                    brew install --cask docker
                    INSTALLED_SOMETHING=1
                    echo -n "  Docker Desktop açılana kadar bekleyin, sonra Enter'a basın... "
                    read -r
                    open -a Docker 2>/dev/null || true
                    echo -n "  Docker daemon hazır olana kadar bekleyin, sonra Enter'a basın... "
                    read -r
                fi
            else
                echo ""
                log_fail "Docker bulunamadı. Lütfen kurun:"
                echo -e "    ${BOLD}macOS:${NC} https://docs.docker.com/desktop/install/mac-install/"
                echo -e "    veya: brew install --cask docker"
                echo ""
                echo -n "  Docker kurulduysa ve hazırsa Enter'a basın (iptal: Ctrl+C)... "
                read -r
            fi

        elif [ "$PLATFORM" = "wsl" ]; then
            echo ""
            log_fail "WSL2'de Docker bulunamadı."
            echo -e "    ${BOLD}Seçenek 1:${NC} Docker Desktop for Windows + WSL2 backend"
            echo -e "              https://docs.docker.com/desktop/install/windows-install/"
            echo -e "    ${BOLD}Seçenek 2:${NC} WSL2 içinde native Docker:"
            echo -e "              sudo apt-get install docker.io docker-compose-plugin"
            echo ""
            echo -n "  Docker kurulduysa ve hazırsa Enter'a basın (iptal: Ctrl+C)... "
            read -r

        elif [ "$PLATFORM" = "debian" ]; then
            if ask_yes_no "Docker kurulumsun mu? (apt-get: docker.io + compose plugin)"; then
                sudo apt-get update -qq
                sudo apt-get install -y -qq docker.io docker-compose-plugin
                sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true
                sudo usermod -aG docker "$USER" 2>/dev/null || true
                INSTALLED_SOMETHING=1
                echo -n "  Docker daemon başlatılıyor... "
                sleep 3
            else
                echo ""
                log_fail "Docker bulunamadı. Lütfen kurun:"
                echo -e "    ${BOLD}Debian/Ubuntu:${NC} sudo apt-get install docker.io docker-compose-plugin"
                echo -e "    ${BOLD}Resmi:${NC} https://docs.docker.com/engine/install/"
                echo ""
                echo -n "  Docker kurulduysa ve hazırsa Enter'a basın (iptal: Ctrl+C)... "
                read -r
            fi

        elif [ "$PLATFORM" = "fedora" ]; then
            if ask_yes_no "Docker kurulumsun mu? (dnf: docker + compose plugin)"; then
                sudo dnf install -y -q docker docker-compose-plugin
                sudo systemctl start docker 2>/dev/null || true
                sudo usermod -aG docker "$USER" 2>/dev/null || true
                INSTALLED_SOMETHING=1
                sleep 3
            else
                echo ""
                log_fail "Docker bulunamadı. Lütfen kurun:"
                echo -e "    ${BOLD}Fedora:${NC} sudo dnf install docker docker-compose-plugin"
                echo ""
                echo -n "  Docker kurulduysa ve hazırsa Enter'a basın (iptal: Ctrl+C)... "
                read -r
            fi

        else
            echo ""
            log_fail "Docker bulunamadı. Kurulum: https://docs.docker.com/get-docker/"
            echo -n "  Docker kurulduysa ve hazırsa Enter'a basın (iptal: Ctrl+C)... "
            read -r
        fi

        if ! check_cmd docker; then
            log_fail "Docker hâlâ bulunamadı. Kurulum sonrası terminali yeniden açın."
            exit 1
        fi
    fi

    log_ok "docker     : $(version_of docker)"

    if ! docker info &>/dev/null; then
        log_warn "Docker daemon çalışmıyor"

        if [ "$PLATFORM" = "macos" ]; then
            log_dim "Docker Desktop başlatılıyor..."
            open -a Docker 2>/dev/null || true
            echo -n "  Docker daemon hazır olana kadar bekleyin, sonra Enter'a basın... "
            read -r
        elif [ "$PLATFORM" = "debian" ] || [ "$PLATFORM" = "wsl" ]; then
            sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true
            sleep 3
        elif [ "$PLATFORM" = "fedora" ]; then
            sudo systemctl start docker 2>/dev/null || true
            sleep 3
        fi

        local retries=0
        while ! docker info &>/dev/null && [ $retries -lt 30 ]; do
            sleep 2
            retries=$((retries + 1))
            echo -n "."
        done
        echo ""

        if ! docker info &>/dev/null; then
            log_fail "Docker daemon başlatılamadı. Docker Desktop'ı açıp tekrar deneyin."
            exit 1
        fi
    fi

    log_ok "docker daemon : çalışıyor"

    if docker compose version &>/dev/null; then
        log_ok "compose    : $(docker compose version --short 2>/dev/null || echo 'mevcut')"
    else
        log_warn "docker compose plugin bulunamadı"
        if [ "$PLATFORM" = "debian" ] || [ "$PLATFORM" = "wsl" ]; then
            if ask_yes_no "docker-compose-plugin kurulumsun mu?"; then
                sudo apt-get update -qq && sudo apt-get install -y -qq docker-compose-plugin
                INSTALLED_SOMETHING=1
            fi
        elif [ "$PLATFORM" = "fedora" ]; then
            if ask_yes_no "docker-compose-plugin kurulumsun mu?"; then
                sudo dnf install -y -q docker-compose-plugin
                INSTALLED_SOMETHING=1
            fi
        fi

        if ! docker compose version &>/dev/null; then
            log_fail "docker compose bulunamadı. Kurulum: https://docs.docker.com/compose/install/"
            exit 1
        fi
        log_ok "compose    : kuruldu"
    fi

    return 0
}

check_wireshark() {
    local found=false

    if check_cmd wireshark; then
        found=true
    elif [ "$PLATFORM" = "macos" ]; then
        if [ -d "/Applications/Wireshark.app" ]; then
            found=true
        fi
    fi

    if $found; then
        log_ok "wireshark  : mevcut"
        return 0
    fi

    log_warn "Wireshark bulunamadı (pcap dosyalarını açmak için gerekli)"

    if [ "$PLATFORM" = "macos" ]; then
        if check_cmd brew; then
            if ask_yes_no "Wireshark kurulumsun mu? (brew install --cask wireshark)"; then
                brew install --cask wireshark
                INSTALLED_SOMETHING=1
            fi
        else
            log_dim "Kurulum: brew install --cask wireshark"
            log_dim "  veya: https://www.wireshark.org/download.html"
        fi
    elif [ "$PLATFORM" = "debian" ] || [ "$PLATFORM" = "wsl" ]; then
        if ask_yes_no "Wireshark kurulumsun mu? (sudo apt-get install -y wireshark)"; then
            sudo apt-get update -qq
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireshark wireshark-qt 2>/dev/null || \
                sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireshark tshark
            INSTALLED_SOMETHING=1
        fi
    elif [ "$PLATFORM" = "fedora" ]; then
        if ask_yes_no "Wireshark kurulumsun mu? (sudo dnf install -y wireshark)"; then
            sudo dnf install -y -q wireshark
            INSTALLED_SOMETHING=1
        fi
    elif [ "$PLATFORM" = "arch" ]; then
        if ask_yes_no "Wireshark kurulumsun mu? (sudo pacman -S --noconfirm wireshark-qt)"; then
            sudo pacman -S --noconfirm wireshark-qt
            INSTALLED_SOMETHING=1
        fi
    elif [ "$PLATFORM" = "alpine" ]; then
        log_dim "Alpine'de Wireshark: sudo apk add wireshark"
    fi

    if ! check_cmd wireshark && ! [ -d "/Applications/Wireshark.app" ]; then
        log_dim "Wireshark olmadan pcap dosyalarını açamazsınız."
        log_dim "Kurulum: https://www.wireshark.org/download.html"
        log_dim "Lab ortamı kurulacak, Wireshark'ı daha sonra kurabilirsiniz."
    fi

    return 0
}

# ─── Health Check Polling ───────────────────────────────────────

wait_for_services() {
    local max_wait=120
    local elapsed=0
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

    echo -n "  "

    while [ $elapsed -lt $max_wait ]; do
        local all_ready=true

        for container in shark-tank-web shark-tank-https shark-tank-dns shark-tank-tcp-echo shark-tank-ftp shark-tank-smtp shark-tank-udp-echo shark-tank-icmp-target shark-tank-attacker shark-tank-voip shark-tank-dhcp-server shark-tank-dhcp-client shark-tank-imap shark-tank-client; do
            local state
            state=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "missing")
            if [ "$state" != "running" ]; then
                all_ready=false
                break
            fi
        done

        if $all_ready; then
            local client_ok=false
            if docker exec shark-tank-client curl -sf http://172.50.2.10/ >/dev/null 2>&1; then
                client_ok=true
            fi

            if $client_ok; then
                echo ""
                return 0
            fi
        fi

        local idx=$((elapsed % 10))
        printf "\r  %s Servisler başlatılıyor... (%ds) " "${spin:$idx:1}" "$elapsed"
        sleep 3
        elapsed=$((elapsed + 3))
    done

    echo ""
    log_warn "Bazı servisler ${max_wait}s içinde hazır olmadı, devam ediliyor..."
    return 0
}

# ─── Main Setup ─────────────────────────────────────────────────

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        Shark-Tank  Wireshark Network Analysis Lab        ║${NC}"
echo -e "${CYAN}║              Tek Komutla Kurulum                     ║${NC}"
echo -e "${CYAN}║            Platform: ${PLATFORM}                          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 0: Prerequisites ──
echo -e "${YELLOW}[0/7]${NC} ${BOLD}Önkoşullar kontrol ediliyor...${NC}"
echo ""

PREREQ_FAIL=0

check_bash    || PREREQ_FAIL=1
check_git     || PREREQ_FAIL=1
check_make    || PREREQ_FAIL=1
check_openssl || PREREQ_FAIL=1
check_python3 || PREREQ_FAIL=1
check_docker  || PREREQ_FAIL=1
check_wireshark

if [ $PREREQ_FAIL -ne 0 ]; then
    echo ""
    log_fail "Bazı zorunlu araçlar kurulamadı. Yukarıdaki hataları düzeltip tekrar deneyin."
    exit 1
fi

if [ "$INSTALLED_SOMETHING" -eq 1 ]; then
    echo ""
    log_dim "Yeni kurulan araçlar için PATH güncellemesi gerekebilir."
    log_dim "Sorun yaşarsanız terminali kapatıp yeniden açın."
fi

# ── Step 1: SSL Certificate ──
echo ""
echo -e "${YELLOW}[1/7]${NC} ${BOLD}SSL sertifika kontrolü...${NC}"
mkdir -p shared/certs shared/pcaps
if [ ! -f shared/certs/server.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout shared/certs/server.key \
        -out shared/certs/server.crt \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Shark-Tank/OU=Network Analysis Lab/CN=secure.shark-tank.local" 2>/dev/null
    log_ok "Sertifika oluşturuldu"
else
    log_ok "Sertifika mevcut"
fi

# ── Step 2: Docker Build ──
echo ""
echo -e "${YELLOW}[2/7]${NC} ${BOLD}Docker image'lar build ediliyor...${NC}"
docker compose build 2>&1
log_ok "Image'lar hazır"

# ── Step 3: Docker Up ──
echo ""
echo -e "${YELLOW}[3/7]${NC} ${BOLD}Container'lar başlatılıyor...${NC}"
docker compose up -d 2>&1
log_ok "Container'lar başlatıldı"

# ── Step 4: Wait for Services ──
echo ""
echo -e "${YELLOW}[4/7]${NC} ${BOLD}Servisler hazır olana kadar bekleniyor...${NC}"
wait_for_services

# ── Step 5: Connection Tests ──
echo ""
echo -e "${YELLOW}[5/7]${NC} ${BOLD}Bağlantı testleri...${NC}"
FAIL=0

docker exec shark-tank-client curl -sf http://172.50.2.10/ >/dev/null 2>&1 \
    && log_ok "HTTP    (172.50.2.10:80)"   || { log_fail "HTTP"; FAIL=1; }

docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local +short >/dev/null 2>&1 \
    && log_ok "DNS     (172.50.2.11:53)"   || { log_fail "DNS"; FAIL=1; }

docker exec shark-tank-client nc -z -w 1 172.50.2.12 8080 2>/dev/null \
    && log_ok "TCP     (172.50.2.12:8080)" || { log_fail "TCP Echo"; FAIL=1; }

docker exec shark-tank-client curl -skf https://172.50.2.13/ >/dev/null 2>&1 \
    && log_ok "HTTPS   (172.50.2.13:443)"  || { log_fail "HTTPS"; FAIL=1; }

docker exec shark-tank-client ping -c 1 -W 2 172.50.2.14 >/dev/null 2>&1 \
    && log_ok "ICMP    (172.50.2.14)"      || { log_fail "ICMP"; FAIL=1; }

docker exec shark-tank-client nc -z -w 2 172.50.2.15 21 2>/dev/null \
    && log_ok "FTP     (172.50.2.15:21)"   || { log_fail "FTP"; FAIL=1; }

if [ $FAIL -eq 1 ]; then
    echo ""
    log_warn "Bazı servisler henüz hazır olmamış olabilir."
    log_dim "make test ile tekrar kontrol edebilirsiniz."
fi

# ── Step 6: Pcap Generation ──
echo ""
echo -e "${YELLOW}[6/7]${NC} ${BOLD}Pcap dosyaları oluşturuluyor...${NC}"
chmod +x scripts/generate-traffic.sh
./scripts/generate-traffic.sh all
chmod +x scripts/download-sample-pcaps.sh
./scripts/download-sample-pcaps.sh

# ── Step 7: Summary ──
echo ""
echo -e "${YELLOW}[7/7]${NC} ${BOLD}Son kontroller...${NC}"
PCAP_COUNT=$(ls -1 shared/pcaps/*.pcap 2>/dev/null | wc -l | tr -d ' ')
log_ok "${PCAP_COUNT} pcap dosyası hazır"

CONTAINER_COUNT=$(docker compose ps --format '{{.Name}}' 2>/dev/null | wc -l | tr -d ' ')
log_ok "${CONTAINER_COUNT} container çalışıyor"

# ── Final Summary ──
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║               ${BOLD}${GREEN}KURULUM TAMAMLANDI${NC}${CYAN}                          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Ağ:${NC} shark-tank (172.50.2.0/24)"
echo ""
echo -e "  ${BOLD}Servisler:${NC}"
echo "    Web (HTTP)    172.50.2.10:80"
echo "    DNS           172.50.2.11:53"
echo "    TCP Echo      172.50.2.12:8080"
echo "    HTTPS         172.50.2.13:443"
echo "    ICMP Target   172.50.2.14"
echo "    FTP           172.50.2.15:21  (${FTP_USER:-ftpuser} / ${FTP_PASS:-ftppass123})"
echo "    Client        172.50.2.100"
echo "    Attacker      172.50.2.200"
echo ""
echo -e "  ${BOLD}Sonraki adım:${NC}"
echo "    make open FILE=shared/pcaps/module-13-http.pcap"
echo ""
echo -e "  ${BOLD}Rehber:${NC}"
echo "    module-01-basics/module-01-basics.md"
echo ""
echo -e "  ${BOLD}Diğer komutlar:${NC}"
echo "    make status    # Durum kontrolü"
echo "    make test      # Bağlantı testi"
echo "    make capture   # Pcap'ları yeniden üret"
echo "    make logs      # Container logları"
echo "    make shell     # Client container'a bağlan"
echo "    make clean     # Her şeyi sil"
echo ""
