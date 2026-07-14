# shark-tank -- Wireshark Network Analysis Lab

Docker tabanlı, tek komutla ayağa kalkan Wireshark eğitim laboratuvarı. Gerçek ağ trafiği üreterek paket analizini sıfırdan ileri seviyeye öğretir. 25 modül, 22 pcap, 14 gerçek servis: hepsi kendi makinenizde, izole bir ağda.

**macOS / Linux / Windows (WSL2)**: her platformda çalışır.

---

## Kim İçin?

| Rol | Neden Faydalı? | Hangi Modüller? |
|----|----------------|-----------------|
| **WCNA adayları** | Sınav syllabus'unun %90+'ı uygulamalı işlenir. Display filter, Expert Info, TCP grafikleri, tshark: sınavın en çok puan getiren konuları | Tümü (M01-M25) |
| **SOC L1 analistleri** | Alert triage'da pcap analizi yapmayı öğrenir. Port scan, C2 beaconing, DNS exfiltration, credential sızıntısı tespiti | M01-M02, M08, M13, M24-M25 |
| **CompTIA Network+ adayları** | Paket analiz bölümünü gerçek trafik üzerinde uygular. TCP/UDP, DHCP, DNS, ARP, IPv6 | M01-M12 |
| **CompTIA Security+ adayları** | Trafik analizi bölümünü saldırı senaryolarıyla çalışır. SQL injection, XSS, SYN flood, TLS zafiyetleri | M13-M25 |
| **Ağ mühendisleri** | Performans analizi ve troubleshooting yapmayı öğrenir. Retransmission, zero window, RTT, throughput grafikleri | M08-M11, M19-M20 |
| **Siber güvenlik öğrencileri** | Kill chain'i pcap'te adım adım takip eder. Reconnaissance → delivery → exploitation → C2 → exfiltration | M23-M25 |
| **CEH adayları** | Ağ forensics bölümünde saldırı izlerini paket seviyesinde görür | M25 |

---

## Ne Öğreneceksin?

- **Wireshark'ı etkin kullanma**: 3 panel, renk kodları, display filter, Expert Info, Follow TCP Stream
- **Protokol analizi**: TCP/IP katmanlarını (ARP, IP, TCP, UDP, DNS, HTTP, TLS) gerçek paketlerle inceleme
- **Saldırı tespiti**: Port scan, SYN flood, SQL injection, XSS, C2 beaconing, DNS exfiltration, credential sızıntısı
- **Performans analizi**: Retransmission, zero window, RTT, throughput, TCP congestion control grafikleri
- **tshark otomasyonu**: Komut satırından pcap analizi, script yazma, toplu işleme
- **TLS analizi**: Handshake, cipher suite, sertifika inceleme, SSLKEYLOGFILE ile trafiği deşifre etme
- **VoIP analizi**: SIP sinyalleşme, RTP ses akışı, jitter/packet loss ölçümü
- **Forensics**: Kill chain oluşturma, trafik profili çıkarma, anomali tespiti

---

## Hızlı Başlangıç

### Seçenek A: Sadece Pcap Analizi (Docker Gerekmez)

Repo'yu klonla, pcap'i Wireshark'ta aç, öğrenmeye başla. Docker kurmana gerek yok.

```bash
git clone https://github.com/nuriacar/shark-tank.git
cd shark-tank

# macOS:
open -a Wireshark shared/pcaps/module-01-basics.pcap

# Linux:
wireshark shared/pcaps/module-01-basics.pcap &

# Windows:
start wireshark shared\pcaps\module-01-basics.pcap
```

22 pcap dosyası ve TLS keylog dosyası repo'ya dahildir. Modül rehberlerini (`module-XX/module-XX.md`) aç, adımları takip et.

### Seçenek B: Tam Laboratuvar (Docker İle)

Gerçek servisler (web, DNS, FTP, VoIP, attacker) üzerinde kendi trafiğini üretmek ve capture almak için:

```bash
git clone https://github.com/nuriacar/shark-tank.git
cd shark-tank
make setup
```

Bu tek komut her şeyi yapar: Docker kurulumu (eksikse), sertifikaları, 14 container'ı, 22 pcap dosyasını.

Kurulum bittikten sonra herhangi bir modülü aç:

```bash
# İlk modülden başla:
make open FILE=shared/pcaps/module-01-basics.pcap

# Tüm pcap'ları yeniden üret (istersen):
make capture

# Servislerin çalıştığını doğrula:
make test
```

### Gereksinimler

`make setup` bunları otomatik kontrol eder ve eksikse kurulum sunar:

| Araç | Zorunlu | Otomatik Kurulum |
|------|---------|------------------|
| Docker (v20+) | Evet | Sorarak |
| Wireshark | Evet | Sorarak |
| openssl | Evet | Sorarak |
| python3 | Evet | Sorarak |
| make + bash + git | Evet | Zaten mevcut |

---

## Neden shark-tank?

| Özellik | Açıklama |
|---------|----------|
| **Docker gerekmez** | 22 pcap repo'ya dahil. Sadece klonla, Wireshark'ta aç, öğren |
| **14 gerçek servis** | web, dns, ftp, smtp, imap, voip, https, dhcp, tcp/udp echo, attacker |
| **22 otomatik pcap** | Her modül için gerçek trafik üretilir: sentetik değil |
| **Saldırı simülasyonu** | Port scan, SYN flood, SQL injection, XSS, C2 beaconing, DNS exfiltration |
| **TLS decryption** | SSLKEYLOGFILE ile şifreli HTTPS trafiğini deşifre etme alıştırması |
| **VoIP + RTP** | 153 RTP paketi, SIP çağrı akışı, jitter analizi |
| **TCP anomaly zengini** | Retransmission, duplicate ACK, SACK, zero window, keep-alive: hepsi gerçek |
| **C2 beaconing** | Düzenli aralıklı çağrılarla IO Graph'te periyodik desen tespiti |
| **tshark otomasyonu** | CLI tabanlı analiz, bash script'leri, toplu pcap işleme |
| **Filtre cheat sheet** | 200+ display filter + capture filter + tshark örneği |
| **Otomatik doğrulama** | `make validate`: 62 kontrol ile pcap içeriklerini doğrula |
| **Çapraz platform** | macOS (Intel + ARM), Linux, Windows WSL2 |
| **İzole lab ağı** | 172.50.2.0/24: host ağdan tamamen bağımsız |

---

## Ağ Topolojisi

```
                    Shark-Tank Network (172.50.2.0/24)
                    ================================

  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
  │ WEB SERVER  │  │ DNS SERVER  │  │  TCP ECHO   │
  │  nginx      │  │  CoreDNS    │  │   socat     │
  │ .10:80      │  │  .11:53     │  │ .12:8080    │
  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
         │                │                │
  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
  │ HTTPS SERVER│  │ ICMP TARGET │  │  FTP SERVER │
  │  nginx+SSL  │  │   Alpine    │  │   vsftpd    │
  │ .13:443     │  │   .14       │  │ .15:21      │
  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
         │                │                │
  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
  │ SMTP SERVER │  │  UDP ECHO   │  │ IMAP SERVER │
  │  Mailpit    │  │   socat     │  │  Dovecot    │
  │ .16:1025    │  │ .17:9090    │  │ .18:110/143 │
  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
         │                │                │
         └────────────────┼────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
       ┌──────┴──────┐        ┌──────┴──────┐
       │   CLIENT    │        │  ATTACKER   │
       │   .100      │        │   .200      │
       │ curl, dig,  │        │ nmap, nc,   │
       │ nmap, nc    │        │ python3     │
       └─────────────┘        └─────────────┘

  VoIP (.22:5060)     DHCP Server (.9.2:67)
  Asterisk SIP/RTP    ISC dhcpd
```

---

## Servisler ve Credentials

| Servis | IP | Port | Kullanıcı | Şifre |
|--------|-----|------|-----------|-------|
| Web (HTTP) | 172.50.2.10 | 80 | admin | secret123 |
| Web (HTTP) | 172.50.2.10 | 80 | employee | companySecret2024 |
| Web (HTTP) | 172.50.2.10 | 80 | guest | wrong (hatalı giriş) |
| HTTPS | 172.50.2.13 | 443 | - | (self-signed) |
| FTP | 172.50.2.15 | 21 | ftpuser | ftppass123 |
| FTP | 172.50.2.15 | 21 | ftpuser | wrongpassword (brute force) |
| SMTP | 172.50.2.16 | 1025 | kullanici | secret123 |
| IMAP/POP3 | 172.50.2.18 | 110/143 | kullanici | secret123 |
| VoIP (SIP) | 172.50.2.22 | 5060 | 1000 / 1001 | voip123 / voip456 |
| DNS | 172.50.2.11 | 53 | - | shark-tank.local zone |
| TCP Echo | 172.50.2.12 | 8080 | - | - |
| UDP Echo | 172.50.2.17 | 9090 | - | - |
| ICMP Target | 172.50.2.14 | - | - | - |
| DHCP Server | 172.50.9.2 | 67 | - | - |
| DHCP Client | dynamic | 68 | - | - |
| Client | 172.50.2.100 | - | - | curl, dig, nmap, nc |
| Attacker | 172.50.2.200 | - | - | nmap, nc, python3 |

Tüm bilgiler [`shared/credentials.env`](shared/credentials.env) dosyasında.

---

## Modüller

| # | Modül | Konu | Seviye |
|---|-------|------|--------|
| 01 | [Temeller](module-01-basics/module-01-basics.md) | Wireshark arayüzü, paket yapısı | Başlangıç |
| 02 | [Filtreleme](module-02-filters/module-02-filters.md) | Display/capture filter, Coloring Rules, Expert Info | Başlangıç |
| 03 | [ARP](module-03-arp/module-03-arp.md) | MAC-IP eşleştirme, gratuitous ARP, spoofing | Başlangıç |
| 04 | [DHCP](module-04-dhcp/module-04-dhcp.md) | DORA süreci, lease time, options | Başlangıç |
| 05 | [ICMP](module-05-icmp/module-05-icmp.md) | Ping, RTT, TTL, tunneling tespiti | Başlangıç |
| 06 | [Fragmentation](module-06-fragmentation/module-06-fragmentation.md) | IP fragmentation, reassembly, PMTUD | Başlangıç |
| 07 | [IPv6](module-07-ipv6/module-07-ipv6.md) | IPv6 header, NDP, SLAAC, AAAA | Orta |
| 08 | [TCP](module-08-tcp/module-08-tcp.md) | 3-way handshake, flags, port scan | Orta |
| 09 | [TCP Dizi](module-09-tcp-sequence/module-09-tcp-sequence.md) | Retransmission, duplicate ACK, SACK | Orta |
| 10 | [UDP](module-10-udp/module-10-udp.md) | Connectionless, port unreachable | Orta |
| 11 | [İleri TCP](module-11-advanced-tcp/module-11-advanced-tcp.md) | Window scaling, keep-alive, zero window | Orta |
| 12 | [DNS](module-12-dns/module-12-dns.md) | Kayıt tipleri, NXDOMAIN, exfiltration | Orta |
| 13 | [HTTP](module-13-http/module-13-http.md) | GET/POST, status codes, Export Objects, SQLi/XSS | Orta |
| 14 | [FTP](module-14-ftp/module-14-ftp.md) | Cleartext credentials, PASV, brute force | Orta |
| 15 | [Email](module-15-email/module-15-email.md) | SMTP/POP3/IMAP, AUTH LOGIN | Orta |
| 16 | [TLS](module-16-tls/module-16-tls.md) | Handshake, cipher, sertifika, SSLKEYLOGFILE decryption | İleri |
| 17 | [tshark CLI](module-17-tshark/module-17-tshark.md) | Komut satırı analizi, otomasyon | İleri |
| 18 | [Gelişmiş Capture](module-18-advanced-capture/module-18-advanced-capture.md) | Ring buffer, profiles, mergecap | İleri |
| 19 | [TCP Grafikleri](module-19-tcp-graph/module-19-tcp-graph.md) | IO/Throughput/RTT graphs | İleri |
| 20 | [Performans](module-20-performance/module-20-performance.md) | Zero window, retransmission oranı | İleri |
| 21 | [WLAN](module-21-wlan/module-21-wlan.md) | 802.11 frame'leri, WPA handshake | İleri |
| 22 | [VoIP](module-22-voip/module-22-voip.md) | SIP/RTP, Telephony menüsü, jitter | İleri |
| 23 | [Baseline](module-23-baseline/module-23-baseline.md) | Trafik profili, anomali tespiti | Sentez |
| 24 | [Sınav Pratiği](module-24-exam-practice/module-24-exam-practice.md) | 9 senaryo, 24 soru, kill chain | Sentez |
| 25 | [Forensics](module-25-forensics/module-25-forensics.md) | Port scan, C2, SQLi, XSS, exfiltration | Sentez |

Her modülde: teori, adım adım alıştırmalar, filtre referansı, sınav soruları + cevaplar.

---

## Nasıl Çalışılır?

**Docker'sız (sadece pcap analizi):** Her modülün pcap dosyası repo'da hazır gelir. Wireshark'ta aç, modül rehberini oku, alıştırmaları yap. Docker kurmana gerek yok.

**Docker ile (tam laboratuvar):** `make setup` ile 14 gerçek servis ayağa kalkar. Kendi trafiğini üret, capture al, gerçek zamanlı analiz yap.

1. **Modül rehberini oku**: `module-XX/module-XX.md` dosyasını aç
2. **Pcap'i Wireshark'ta aç**: `make open FILE=shared/pcaps/module-XX-name.pcap`
3. **Alıştırmaları yap**: Rehberdeki adımları sırayla uygula
4. **Sınav sorularını çöz**: Cevapları `<details>` ile kontrol et
5. **Sonraki modüle geç**: Her modülün sonunda "Sonraki Modül" linki var

```bash
# İpucu: Tüm komutları görmek için
make help

# Servis durumunu kontrol et
make test

# Pcap'lerin içeriğini doğrula
make validate
```

---

## Komut Referansı

```bash
make setup          # İlk kurulum (her şey)
make start          # Container'ları başlat
make stop           # Durdur
make test           # 13 servis bağlantı testi
make capture        # Tüm pcap'ları yeniden üret
make validate       # Pcap içeriklerini doğrula (62 kontrol)
make check          # Modül + pcap dosya kontrolü
make open FILE=...  # Pcap'i Wireshark'ta aç
make status         # Container + ağ durumu
make shell          # Client container'da bash aç
make logs           # Container loglarını izle
make clean          # Her şeyi sil
```

---

## Sertifikalar

| Sertifika | Kapsam |
|-----------|--------|
| **Wireshark WCNA** | M01-M25 tam kapsam (%90+ syllabus, 33 WCNA başlığı) |
| **CompTIA Network+** | Paket analiz bölümü (M01-M12) |
| **CompTIA Security+** | Trafik analizi bölümü (M13-M25) |
| **CEH** | Ağ forensics bölümü (M25) |

---

## Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| Docker başlatılamıyor | Docker Desktop'ı başlatın veya `sudo systemctl start docker` |
| Container'lar hazır değil | `sleep 15 && make test` |
| Pcap dosyaları boş | `make capture` |
| DNS çözümlenmiyor | `docker exec shark-tank-client dig @172.50.2.11 web.shark-tank.local` |
| Build hatası | `docker compose build --no-cache` |

Daha fazla yardım: [GitHub Issues](https://github.com/nuriacar/shark-tank/issues)

---

## Proje Yapısı

```
shark-tank/
├── docker-compose.yml           # 14 servis, izole ağ
├── .env                         # Docker Compose değişkenleri
├── Makefile                     # Tüm komutlar
├── module-01 .. module-25/      # 25 modül rehberi
├── shared/
│   ├── Dockerfile.*             # 7 Docker image
│   ├── credentials.env          # Login bilgileri
│   ├── coredns/                 # DNS zone (shark-tank.local)
│   ├── certs/                   # SSL sertifika + keylog (otomatik)
│   └── pcaps/                   # 22 pcap dosyası (otomatik)
├── scripts/
│   ├── setup.sh                 # Kurulum
│   ├── generate-traffic.sh      # Trafik üretici (21 mod)
│   ├── validate-pcaps.sh        # Pcap doğrulayıcı (62 kontrol)
│   └── ...
└── docs/
    ├── curriculum.md            # Müfredat (~18 saat)
    ├── quick-reference.md       # 200+ filtre cheat sheet
    └── ...
```

---

## Lisans

Copyright © 2026 Nuri ACAR. All rights reserved. Tüm hakları saklıdır.

Detay için: [LICENSE](LICENSE)
