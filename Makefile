UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)

ifeq ($(UNAME_S),Darwin)
    OPEN_CMD := open -a Wireshark
    WIRESHARK_INSTALL := brew install --cask wireshark
else ifeq ($(UNAME_S),Linux)
    OPEN_CMD := wireshark
    WIRESHARK_INSTALL := sudo apt-get install -y wireshark
else
    OPEN_CMD := start wireshark
    WIRESHARK_INSTALL := choco install wireshark
endif

.PHONY: setup start stop build clean capture status help modules test open logs shell update restart check

help: ## Bu yardım mesajını göster
	@echo "Shark-Tank Wireshark Network Analysis Lab"
	@echo "Platform: $(UNAME_S)"
	@echo ""
	@echo "Komutlar:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Docker image'larını derle
	docker compose build

setup: ## İlk kurulum: önkoşullar + build + start + pcap üretimi
	@chmod +x scripts/setup.sh
	./scripts/setup.sh

start: ## Container'lari başlat
	docker compose up -d
	@sleep 3
	@echo "Container durumlari:"
	@docker compose ps

stop: ## Container'lari durdur
	docker compose down
	@echo "Container'lar durduruldu."

restart: ## Container'lari yeniden başlat
	docker compose restart
	@sleep 3
	@echo "Container durumlari:"
	@docker compose ps

clean: ## Her şeyi temizle (onay ister)
	@chmod +x scripts/clean.sh
	./scripts/clean.sh

capture: ## Tüm modüllerin pcap'larini oluştur
	@chmod +x scripts/generate-traffic.sh scripts/download-sample-pcaps.sh
	./scripts/generate-traffic.sh all
	./scripts/download-sample-pcaps.sh

status: ## Container ve ağ durumunu göster
	@echo "=== Container Durumlari ==="
	@docker compose ps
	@echo ""
	@echo "=== Ağ ==="
	@docker network ls | grep shark-tank || true
	@echo ""
	@echo "=== Pcap Dosyalari ==="
	@ls -lh shared/pcaps/*.pcap 2>/dev/null || echo "  (boş - make capture çalıştırın)"

modules: ## Modül listesini göster
	@echo "Shark-Tank Modüller (25 modül):"
	@echo "  01  - Temeller            module-01-basics/module-01-basics.md"
	@echo "  02  - Filtreleme          module-02-filters/module-02-filters.md"
	@echo "  03  - ARP Analizi         module-03-arp/module-03-arp.md"
	@echo "  04  - DHCP Analizi        module-04-dhcp/module-04-dhcp.md"
	@echo "  05  - ICMP Analizi        module-05-icmp/module-05-icmp.md"
	@echo "  06  - Fragmentation       module-06-fragmentation/module-06-fragmentation.md"
	@echo "  07  - IPv6 Analizi        module-07-ipv6/module-07-ipv6.md"
	@echo "  08  - TCP Temel           module-08-tcp/module-08-tcp.md"
	@echo "  09  - TCP Dizi Analizi    module-09-tcp-sequence/module-09-tcp-sequence.md"
	@echo "  10  - UDP Analizi         module-10-udp/module-10-udp.md"
	@echo "  11  - TCP Akış Analizi    module-11-advanced-tcp/module-11-advanced-tcp.md"
	@echo "  12  - DNS Analizi         module-12-dns/module-12-dns.md"
	@echo "  13  - HTTP Analizi        module-13-http/module-13-http.md"
	@echo "  14  - FTP Analizi         module-14-ftp/module-14-ftp.md"
	@echo "  15  - Email Analizi       module-15-email/module-15-email.md"
	@echo "  16  - TLS Analizi         module-16-tls/module-16-tls.md"
	@echo "  17  - tshark CLI          module-17-tshark/module-17-tshark.md"
	@echo "  18  - Gelişmiş Capture    module-18-advanced-capture/module-18-advanced-capture.md"
	@echo "  19  - TCP Grafikleri      module-19-tcp-graph/module-19-tcp-graph.md"
	@echo "  20  - Performans Analizi  module-20-performance/module-20-performance.md"
	@echo "  21  - WLAN (802.11)       module-21-wlan/module-21-wlan.md"
	@echo "  22  - VoIP (SIP/RTP)      module-22-voip/module-22-voip.md"
	@echo "  23  - Baseline Analizi    module-23-baseline/module-23-baseline.md"
	@echo "  24  - Sınav Pratiği       module-24-exam-practice/module-24-exam-practice.md"
	@echo "  25  - Ağ Forensics        module-25-forensics/module-25-forensics.md"

test: ## Bağlantı testleri
	@echo "=== Bağlantı Testleri ==="
	@docker exec shark-tank-client curl -s -o /dev/null -w "  HTTP:   %{http_code}\n" http://172.50.2.10/ 2>/dev/null || echo "  HTTP:   FAIL"
	@result=$$(docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local +short 2>/dev/null | head -1); if [ -n "$$result" ]; then echo "  DNS:    $$result"; else echo "  DNS:    FAIL"; fi
	@docker exec shark-tank-client curl -sk -o /dev/null -w "  HTTPS:  %{http_code}\n" https://172.50.2.13/ 2>/dev/null || echo "  HTTPS:  FAIL"
	@docker exec shark-tank-client ping -c 1 -W 2 172.50.2.14 > /dev/null 2>&1 && echo "  ICMP:   OK" || echo "  ICMP:   FAIL"
	@docker exec shark-tank-client bash -c 'echo test | nc -w 1 172.50.2.12 8080' > /dev/null 2>&1 && echo "  TCP:    OK" || echo "  TCP:    FAIL"
	@docker exec shark-tank-client bash -c 'for i in 1 2 3; do nc -z -w 2 172.50.2.15 21 && exit 0; sleep 2; done; exit 1' 2>/dev/null && echo "  FTP:    OK" || echo "  FTP:    FAIL"
	@docker exec shark-tank-client nc -z -w 2 172.50.2.16 1025 2>/dev/null && echo "  SMTP:   OK" || echo "  SMTP:   FAIL"
	@docker exec shark-tank-client bash -c 'echo test | nc -u -w 1 172.50.2.17 9090' > /dev/null 2>&1 && echo "  UDP:    OK" || echo "  UDP:    FAIL"
	@docker exec shark-tank-client nc -u -z -w 2 172.50.2.22 5060 2>/dev/null && echo "  SIP:    OK" || echo "  SIP:    FAIL"
	@docker exec shark-tank-client nc -z -w 2 172.50.2.18 110 2>/dev/null && echo "  POP3:   OK" || echo "  POP3:   FAIL"
	@docker exec shark-tank-client nc -z -w 2 172.50.2.18 143 2>/dev/null && echo "  IMAP:   OK" || echo "  IMAP:   FAIL"
	@docker ps --format '{{.Names}}' | grep -q "shark-tank-dhcp-server" && echo "  DHCP:   OK" || echo "  DHCP:   FAIL"
	@docker exec shark-tank-attacker ping -c 1 -W 2 172.50.2.10 > /dev/null 2>&1 && echo "  Attacker: OK" || echo "  Attacker: FAIL"

open: ## Pcap dosyasını Wireshark ile aç (make open FILE=...)
	@if [ -z "$(FILE)" ]; then echo "Kullanım: make open FILE=shared/pcaps/module-13-http.pcap"; exit 1; fi
	$(OPEN_CMD) $(FILE)

logs: ## Container loglarını göster (Ctrl+C ile çık)
	docker compose logs -f

shell: ## Client container'da bash aç
	docker exec -it shark-tank-client bash

update: ## Docker image'larını güncelle ve yeniden derle
	docker compose pull
	make build

check: ## Tüm modül dizinlerini ve pcap dosyalarını doğrula
	@echo "=== Modül Dizinleri ==="
	@errors=0; \
	for i in $$(seq -w 1 25); do \
		dir=$$(ls -d module-$$i-* 2>/dev/null | head -1); \
		if [ -n "$$dir" ]; then \
			echo "  [OK] $$dir"; \
		else \
			echo "  [EKSİK] modül $$i bulunamadı"; \
			errors=$$((errors+1)); \
		fi; \
	done; \
	echo ""; \
	echo "=== Pcap Dosyaları ==="; \
	for f in shared/pcaps/module-*.pcap; do \
		if [ -f "$$f" ]; then \
			size=$$(stat -f%z "$$f" 2>/dev/null || stat --format=%s "$$f" 2>/dev/null); \
			echo "  [OK] $$(basename $$f) ($${size} bytes)"; \
		fi; \
	done; \
	echo ""; \
	if [ $$errors -eq 0 ]; then echo "Sonuç: TÜM MODÜLLER TAMAM"; else echo "Sonuç: $$errors modül eksik"; fi

validate: ## Pcap içeriklerini otomatik doğrula
	@chmod +x scripts/validate-pcaps.sh
	./scripts/validate-pcaps.sh
