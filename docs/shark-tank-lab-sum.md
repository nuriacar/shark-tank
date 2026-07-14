# Shark-Tank Network Analysis Lab - Detaylı Özet

## Genel Bakış

Bu lab, Docker üzerinde izole bir ağ ortamı (`shark-tank`, 172.50.2.0/24) kurarak Wireshark paket analizini uygulamalı olarak öğretir. Her modül, belirli bir protokol/konuya odaklanır ve otomatik olarak üretilen pcap dosyaları üzerinde çalışılır.

## Neden Bu Lab?

- **Wireshark sınavda verilen pcap dosyasını analiz etmenizi bekler** - bu lab aynı ortamı simüle eder
- **Protokolleri sadece okuyarak öğrenemezsiniz** - gerçek trafik görerek öğrenilir
- **Docker ile her şey tekrar edilebilir** - istediğiniz kadar trafik üretip yeniden analiz edebilirsiniz
- **Tek komutla ayağa kalkar** - `make setup` ile her şey hazır

---

## Ağ Altyapısı

### Ağ: shark-tank
- **Subnet:** 172.50.2.0/24
- **Gateway:** 172.50.2.1
- **Driver:** Bridge
- **Amaç:** İzole lab ortamı - host ağdan bağımsız

### Servis Envanteri

#### 1. Web Server (HTTP)
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-web` |
| IP | 172.50.2.10 |
| Port | 80 |
| Image | nginx:alpine |
| Endpointler | `/`, `/api/data`, `/api/users`, `/login`, `/secret` (403), `/large`, `/redirect` (302), `/headers`, `/nonexistent` (404) |
| Amaç | HTTP request/response analizi, status codes, POST verisi, redirect |

#### 2. DNS Server
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-dns` |
| IP | 172.50.2.11 |
| Port | 53 (UDP+TCP) |
| Image | coredns/coredns |
| Domain | `shark-tank.local` |
| Kayıtlar | A (web, dns, secure, target, echo, ftp), CNAME (www), MX (mail), NS |
| Amaç | DNS query/response, kayıt tipleri, Transaction ID, NXDOMAIN |

#### 3. TCP Echo Server
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-tcp-echo` |
| IP | 172.50.2.12 |
| Port | 8080 |
| Image | alpine/socat |
| Amaç | TCP 3-way handshake, Seq/Ack takibi, port scanning |

#### 4. HTTPS Server (TLS)
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-https` |
| IP | 172.50.2.13 |
| Port | 443 |
| Image | nginx:alpine + self-signed SSL |
| Sertifika | CN=secure.shark-tank.local, O=Shark-Tank (self-signed) |
| Amaç | TLS handshake, cipher suite, sertifika analizi, şifreli veri |

#### 5. ICMP Target
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-icmp-target` |
| IP | 172.50.2.14 |
| Image | alpine:3.21 |
| Amaç | Ping (Echo Request/Reply), RTT ölçüm, TTL analizi |

#### 6. FTP Server
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-ftp` |
| IP | 172.50.2.15 |
| Port | 21 |
| Credentials | ftpuser / ftppass123 |
| Amaç | FTP command/response, cleartext credentials, active/passive mode |

#### 7. Client (Trafik Üretici)
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-client` |
| IP | 172.50.2.100 |
| Araçlar | curl, dig, drill, ping, tcpdump, nmap, nc, openssl, bash |
| Amaç | Tüm servislerle iletişim kurup trafik üretir, tcpdump ile capture yapar |

#### 8. Attacker
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-attacker` |
| IP | 172.50.2.200 |
| Araçlar | nmap, curl, nc, python3 |
| Amaç | Port scan, SYN flood simülasyonu, şüpheli trafik üretimi |

#### 9. SMTP Server (Mailpit)
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-smtp` |
| IP | 172.50.2.16 |
| Port | 1025 |
| Image | axllent/mailpit |
| Amaç | SMTP email gönderme, cleartext email analizi |

#### 10. UDP Echo Server
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-udp-echo` |
| IP | 172.50.2.17 |
| Port | 9090/UDP |
| Image | alpine/socat |
| Amaç | UDP datagram analizi, port unreachable testi |

#### 11. IMAP Sunucusu (Dovecot)
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-imap` |
| IP | 172.50.2.18 |
| Port | 110 (POP3), 143 (IMAP), 587 (Submission) |
| Image | alpine + dovecot |
| Credentials | kullanici / secret123 |
| Amaç | Email alma (POP3/IMAP), SMTP AUTH, credential sızıntısı |

#### 12. VoIP Sunucusu (Asterisk)
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-voip` |
| IP | 172.50.2.22 |
| Port | 5060/UDP (SIP), 10000-20000/UDP (RTP) |
| Image | alpine + asterisk |
| Extensions | 1000 (voip123), 1001 (voip456) |
| Amaç | SIP çağrı yönetimi, RTP ses iletimi, VoIP analizi |

#### 13. DHCP Server
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-dhcp-server` |
| IP | 172.50.9.2 |
| Port | 67/UDP |
| Ağ | shark-tank-dhcp (172.50.9.0/24) |
| Image | networkboot/dhcpd |
| Amaç | DHCP DORA süreci, IP atama, lease yönetimi |

#### 14. DHCP Client
| Özellik | Değer |
|---------|-------|
| Container | `shark-tank-dhcp-client` |
| IP | dynamic (172.50.9.x) |
| Ağ | shark-tank-dhcp (172.50.9.0/24) |
| Amaç | DHCP Discover/Request gönderir, IP alır |

---

## Modül Detayları

### Modül 01 - Temeller
- Wireshark arayüzü (3 panel)
- Renk kodları
- Capture başlatma
- Paket katmanları (Frame > Ethernet > IP > TCP > Uygulama)
- Follow TCP Stream

### Modül 02 - Filtreleme
- Display filters (sınavda en önemli)
- Capture filters (BPF syntax)
- Protokol, IP, port, flag tabanlı filtreler
- HTTP, DNS, TLS, ICMP, ARP filtreleri
- İleri düzey: retransmission, duplicate ACK, zero window

### Modül 03 - ARP Analizi
- ARP Request (broadcast) / Reply (unicast)
- MAC-IP eşleştirme
- Gratuitous ARP
- ARP poisoning tespiti

### Modül 04 - DHCP Analizi
- DORA süreci (Discover, Offer, Request, ACK)
- DHCP options (Subnet Mask, Router, DNS, Lease Time)
- Source IP 0.0.0.0 nedeni
- UDP port 67/68

### Modül 05 - ICMP Analizi
- Echo Request (Type 8) / Echo Reply (Type 0)
- RTT hesaplama
- TTL analizi
- Farklı boyutlarda ping
- Destination Unreachable (Type 3)

### Modül 06 - IP Fragmentation
- IP parçalama (fragmentation) mekanizması
- Fragment Offset, More Fragments (MF) bayrağı
- Don't Fragment (DF) bayrağı ve PMTUD
- Yeniden birleştirme (reassembly)
- Büyük ping ve UDP ile fragmentation tetikleme

### Modül 07 - IPv6 Analizi
- IPv6 başlık yapısı (vs IPv4)
- Adres tipleri: link-local, global unicast, multicast
- Extension Headers (Fragment, Hop-by-Hop)
- ICMPv6 (Neighbor Solicitation/Advertisement)
- AAAA DNS kayıtları

### Modül 08 - TCP Temel Analizi
- 3-way handshake (SYN → SYN-ACK → ACK)
- Sequence/Acknowledgment number takibi
- TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- Connection teardown (FIN)
- Port scanning tespiti (SYN scan)
- RST paketleri ve kapalı port tespiti

### Modül 09 - TCP Dizi Analizi
- Sequence Number ve Acknowledgment Number derinlemesine
- TCP Window Size ve sliding window
- Retransmission ve Duplicate ACK tespiti
- TCP Zero Window ve flow control
- Ağ gecikmesi/kaybı simülasyonu (netem)
- SACK (Selective Acknowledgment)

### Modül 10 - UDP Analizi
- Connectionless protokol yapısı
- UDP başlık alanları (Source Port, Dest Port, Length, Checksum)
- UDP vs TCP karşılaştırması
- DNS over UDP
- Port Unreachable (ICMP Destination Unreachable)
- UDP ses/görüntü trafiği temelleri

### Modül 11 - İleri TCP Analizi
- TCP Keep-Alive mekanizması
- Window Scaling (WSopt)
- TCP Congestion Control (Slow Start, Congestion Avoidance)
- Nagle algoritması ve delayed ACK
- Zero Window ve TCP flow control
- Büyük veri transferinde TCP segmentasyonu

### Modül 12 - DNS Analizi
- Query/Response eşleştirme (Transaction ID)
- Kayıt tipleri: A, AAAA, CNAME, MX, NS, TXT
- NXDOMAIN hatası
- UDP (ve TCP) tabanlı DNS
- Recursive vs iterative sorgu
- DNS tunneling/exfiltration tespiti

### Modül 13 - HTTP Analizi
- GET, POST, HEAD istekleri
- Status codes: 200, 302, 403, 404
- Header analizi (User-Agent, Content-Type, Server)
- POST body'de şifre görünürlüğü
- Follow TCP Stream ile tam oturum okuma
- HTTP Object Export
- SQL injection ve XSS saldırı tespiti

### Modül 14 - FTP Analizi
- FTP command/response yapısı
- Cleartext credentials (kullanıcı adı + şifre görünür)
- Active vs Passive mode (PORT vs PASV)
- Dosya transferi ve directory listing
- FTP brute force saldırı tespiti

### Modül 15 - Email (SMTP/POP3/IMAP) Analizi
- SMTP komutları (EHLO, MAIL FROM, RCPT TO, DATA)
- SMTP AUTH LOGIN (base64 ile şifre gönderimi)
- POP3 oturumu (USER, PASS, STAT, LIST, RETR)
- IMAP oturumu (LOGIN, SELECT, FETCH)
- Cleartext email içeriği ve credential analizi
- Submission port (587) üzerinden auth

### Modül 16 - TLS Analizi
- TLS handshake adımları (ClientHello, ServerHello, Certificate, ServerHelloDone)
- Cipher suite seçimi
- Sertifika analizi (issuer, subject, CN, validity)
- Self-signed sertifika tespiti
- Şifrelenmiş veri (Application Data)
- HTTP vs HTTPS karşılaştırma
- TLS 1.2 vs TLS 1.3 farkları

### Modül 17 - tshark CLI Analizi
- tshark parametreleri (-r, -Y, -T fields, -e, -z, -q, -c)
- Display filter vs capture filter (-Y vs -f)
- Belirli alanları çıkarma (-T fields -e)
- İstatistikler (-z io,phs, -z conv,tcp, -z expert)
- TCP stream takibi (tshark -z follow)
- Export objects (--export-objects)
- Otomasyon scriptleri (Bash + PowerShell)
- Canlı capture (sudo tshark -i)
- Cross-platform kurulum ve path bilgileri

### Modül 18 - Gelişmiş Capture Teknikleri
- Ring buffer ile sürekli capture
- Multi-file capture (dosya boyutu/süre sınırı)
- Auto-stop koşulları
- Snap length (snaplen) ayarları
- Mergecap ile pcap birleştirme
- Editcap ile pcap düzenleme/kırpma
- Capture filter (BPF) ile ön filtreleme

### Modül 19 - TCP Grafikleri
- IO Graph (zaman bazlı throughput)
- Flow Graph (TCP akış şeması)
- TCP Stream Graphs (Round Trip Time, Throughput, Window Scaling, Sequence Numbers)
- IO Graph ile anomali tespiti
- Wireshark Statistics menüsü

### Modül 20 - Performans Analizi
- Throughput hesaplama (Mbps/paket-saniye)
- RTT (Round Trip Time) analizi
- Retransmission ve paket kaybı oranı
- TCP Window Size ve window scaling
- Wireshark Expert Info kullanımı
- Ağ gecikmesi/kaybı simülasyonu (netem)
- Port exhaustion ve burst trafik

### Modül 21 - WLAN (802.11) Analizi
- 802.11 yönetim çerçeveleri (Beacon, Probe Request/Response)
- Authentication ve Association süreci
- Deauthentication saldırı tespiti
- Radiotap header bilgileri (sinyal, frekans, veri hızı)
- WPA/WPA2 handshake analizi
- Kablolu vs kablosuz karşılaştırması

### Modül 22 - VoIP (SIP/RTP) Analizi
- SIP mesaj yapısı (REGISTER, INVITE, ACK, BYE)
- SIP URI ve header analizi
- RTP stream ve ses iletimi
- Jitter ve latency analizi
- Codec tespiti (ulaw/alaw)
- VoIP çağrı akışı (Wireshark Telephony)

### Modül 23 - Baseline Analizi
- Trafik profili çıkarma (normal/anormal desen)
- Protocol Hierarchy istatistiği
- Conversations ve Endpoints analizi
- Throughput, paket/saniye, ortalama paket boyutu
- Normal trafik ile anomali trafiği karşılaştırma
- Port scan ve SYN flood'un baseline üzerindeki etkisi

### Modül 24 - Sınav Pratiği
- 9 farklı senaryo içeren karışık pcap (24 soru)
- HTTP, DNS, HTTPS, ICMP, TCP, FTP + saldırı
- HTTP forensics (şifre bulma, sayfa tespiti)
- DNS analizi (domain sorguları, IP çözümleme)
- TLS analizi (handshake, sertifika)
- Port scan ve SYN flood tespiti
- FTP analizi (cleartext credentials)
- Kill chain oluşturma
- İstatistik araçları (Protocol Hierarchy, Conversations, Endpoints)

### Modül 25 - Ağ Forensics
- Şüpheli trafik tespiti
- Veri sızıntısı analizi
- DNS exfiltration
- HTTP User-Agent anomalileri
- C2 (Command & Control) pattern'leri ve beaconing
- Zamanlama analizi
- Kill chain adımlarının belirlenmesi

---

## Capture Yaklaşımı

macOS + Docker Desktop ortamında:

1. **Client container** üzerinde `tcpdump` çalışır
2. Client tüm servislere bağlanır (request gönderir + response alır)
3. Her iki yönün trafikleri capture edilir
4. Pcap dosyaları `shared/pcaps/` dizinine yazılır
5. Wireshark ile local dosya açılarak analiz yapılır

Bu yaklaşım:
- macOS'in Docker ağını doğrudan capture edememe sorununu çözer
- Client perspektifinden tüm konuşmaları görür
- Port mapping gerektirmez

---

## DNS Zone: shark-tank.local

| Kayıt | Tip | Değer |
|-------|-----|-------|
| ns1 | A | 172.50.2.11 |
| web | A | 172.50.2.10 |
| dns | A | 172.50.2.11 |
| secure | A | 172.50.2.13 |
| target | A | 172.50.2.14 |
| echo | A | 172.50.2.12 |
| www | CNAME | web.shark-tank.local |
| ftp | A | 172.50.2.15 |
| smtp | A | 172.50.2.16 |
| udp | A | 172.50.2.17 |
| imap | A | 172.50.2.18 |
| voip | A | 172.50.2.22 |
| mail | MX(10) | mail.shark-tank.local |
| mail | A | 172.50.2.16 |

---

## SSL Sertifika Detayları

| Alan | Değer |
|------|-------|
| CN | secure.shark-tank.local |
| O | Shark-Tank |
| OU | Network Analysis Lab |
| C | TR |
| ST | Istanbul |
| Algorithm | RSA 2048 |
| Signature | sha256WithRSAEncryption |
| Validity | 365 gün |
| Tür | Self-signed (issuer = subject) |
