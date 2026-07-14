# shark-tank: Wireshark Network Analysis Lab

Docker tabanlı Wireshark eğitim laboratuvarı. Gerçek ağ trafiği üreterek paket analizini sıfırdan ileri seviyeye öğretir. **25 modül, 22 pcap, 14 gerçek servis.**

---

## Kim İçin?

| Rol | Neden Faydalı? |
|----|----------------|
| **WCNA adayları** | Sınav syllabus'unun %90+'ı uygulamalı işlenir |
| **SOC L1 analistleri** | Alert triage'da pcap analizi: port scan, C2 beaconing, credential sızıntısı tespiti |
| **CompTIA Network+** | Paket analiz bölümünü gerçek trafik üzerinde uygular |
| **CompTIA Security+** | Saldırı senaryolarıyla çalışır: SQL injection, XSS, SYN flood, TLS zafiyetleri |
| **Ağ mühendisleri** | Performans analizi: retransmission, zero window, RTT, throughput grafikleri |
| **Siber güvenlik öğrencileri** | Kill chain'i pcap'te adım adım takip eder |

---

## Nasıl Kullanılır?

### Seçenek A: Sadece Pcap Analizi (Docker Gerekmez)

```bash
git clone https://github.com/nuriacar/shark-tank.git
cd shark-tank
wireshark shared/pcaps/module-01-basics.pcap
```

22 pcap dosyası repo'ya dahildir. Soldaki menüden bir modül seç, rehberi oku, pcap'i Wireshark'ta aç.

### Seçenek B: Tam Laboratuvar (Docker İle)

```bash
git clone https://github.com/nuriacar/shark-tank.git
cd shark-tank
make setup
```

14 gerçek servis ayağa kalkar. Kendi trafiğini üret, capture al, gerçek zamanlı analiz yap.

---

## Ne Öğreneceksin?

- **Wireshark'ı etkin kullanma**: display filter, Expert Info, Follow TCP Stream
- **Protokol analizi**: TCP/IP katmanlarını gerçek paketlerle inceleme
- **Saldırı tespiti**: port scan, SYN flood, SQL injection, XSS, C2 beaconing, DNS exfiltration
- **Performans analizi**: retransmission, zero window, RTT, throughput grafikleri
- **tshark otomasyonu**: komut satırından pcap analizi, script yazma
- **TLS analizi**: handshake, cipher suite, SSLKEYLOGFILE ile deşifre etme
- **VoIP analizi**: SIP sinyalleşme, RTP ses akışı, jitter ölçümü
- **Forensics**: kill chain oluşturma, trafik profili, anomali tespiti

---

## Modüller

| Seviye | Modüller | Konu |
|--------|---------|------|
| **Başlangıç** | M01-M06 | Wireshark temelleri, filtreleme, ARP, DHCP, ICMP, fragmentation |
| **İleri** | M07-M16 | IPv6, TCP/UDP, DNS, HTTP, FTP, Email, TLS |
| **Uzman** | M17-M22 | tshark, gelişmiş capture, TCP grafikleri, performans, WLAN, VoIP |
| **Sentez** | M23-M25 | Baseline analizi, sınav pratiği, ağ forensics |

Soldaki menüden herhangi bir modüle başla. Her modül bağımsız çalışabilir, ama sırayla takip etmek önerilir.

---

## GitHub

[:material-github: nuriacar/shark-tank](https://github.com/nuriacar/shark-tank)

---

Copyright © 2026 Nuri ACAR. All rights reserved. Tüm hakları saklıdır.
