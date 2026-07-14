# Ağ Topoloji Diyagramı

## Genel Görünüm

```
╔══════════════════════════════════════════════════════════════════════════╗
║                       Shark-Tank LABORATUVAR AĞI                            ║
║                172.50.2.0/24 (Bridge)  +  172.50.9.0/24 (DHCP)          ║
║                      Gateway: 172.50.2.1 / 172.50.9.1                   ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐         ║
║   │WEB SERVER │   │DNS SERVER │   │TCP ECHO   │   │ SMTP      │         ║
║   │nginx      │   │CoreDNS    │   │socat      │   │Mailpit    │         ║
║   │172.50.2.10│   │172.50.2.11│   │172.50.2.12│   │172.50.2.16│         ║
║   │:80 HTTP   │   │:53 UDP/TCP│   │:8080 TCP  │   │:1025 SMTP │         ║
║   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘         ║
║         │               │               │               │               ║
║   ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┘         ║
║   │HTTPS      │   │ICMP TARGET│   │FTP SERVER │   │IMAP        │         ║
║   │nginx+SSL  │   │Alpine     │   │vsftpd     │   │POP3/IMAP   │         ║
║   │172.50.2.13│   │172.50.2.14│   │172.50.2.15│   │172.50.2.18 │         ║
║   │:443 TLS   │   │Ping hedefi│   │:21 FTP    │   │:110/143/587│         ║
║   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └──────┬──────┘       ║
║         │               │               │                │               ║
║   ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐         │               ║
║   │UDP ECHO   │   │VOIP       │   │DHCP SERVER│  (DHCP ağı: 172.50.9.x) ║
║   │socat      │   │SIP/RTP    │   │dhcpd      │         │               ║
║   │172.50.2.17│   │172.50.2.22│   │172.50.9.2 │         │               ║
║   │:9090 UDP  │   │:5060 UDP  │   │:67 UDP    │         │               ║
║   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘         │               ║
║         │               │               │               │               ║
║         └───────┬───────┴───────┬───────┘               │               ║
║                 │               │                       │               ║
║   ┌─────────────┴──────┐  ┌────┴──────────┐             │               ║
║   │      CLIENT        │  │   ATTACKER    │             │               ║
║   │    172.50.2.100    │  │  172.50.2.200 │   ┌─────────┴────────┐      ║
║   │                    │  │               │   │  DHCP CLIENT    │      ║
║   │ curl, dig, drill,  │  │ nmap, nc,     │   │  (dynamic IP)   │      ║
║   │ ping, tcpdump,     │  │ curl, python3 │   │  172.50.9.x     │      ║
║   │ nmap, nc, openssl  │  │               │   └─────────────────┘      ║
║   │                    │  │ Port scan,    │                             ║
║   │ Pcap: /pcaps/*.pcap│  │ SYN flood,    │                             ║
║   └────────────────────┘  │ Brute force   │                             ║
║                           └───────────────┘                             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

## Trafik Akışları

### HTTP Akışı
```
CLIENT (172.50.2.100) ──── GET / ──────────▶ WEB (172.50.2.10:80)
CLIENT (172.50.2.100) ◀─── 200 OK HTML ───── WEB (172.50.2.10:80)
```

### DNS Akışı
```
CLIENT (172.50.2.100) ──── Query: web.shark-tank.local A ──▶ DNS (172.50.2.11:53)
CLIENT (172.50.2.100) ◀─── Response: 172.50.2.10 ───────── DNS (172.50.2.11:53)
```

### TLS Akışı
```
CLIENT (172.50.2.100) ──── ClientHello ──────▶ HTTPS (172.50.2.13:443)
CLIENT (172.50.2.100) ◀─── ServerHello ─────── HTTPS (172.50.2.13:443)
CLIENT (172.50.2.100) ◀─── Certificate ─────── HTTPS (172.50.2.13:443)
CLIENT (172.50.2.100) ──── ClientKeyExchange ▶ HTTPS (172.50.2.13:443)
CLIENT (172.50.2.100) ◀═══ Encrypted Data ═══ HTTPS (172.50.2.13:443)
```

### ICMP Akışı
```
CLIENT (172.50.2.100) ──── Echo Request ────▶ ICMP (172.50.2.14)
CLIENT (172.50.2.100) ◀─── Echo Reply ─────── ICMP (172.50.2.14)
```

### FTP Akışı
```
CLIENT (172.50.2.100) ──── TCP SYN ─────────▶ FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ◀─── SYN-ACK ────────── FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ──── ACK ─────────────▶ FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ◀─── 220 Welcome ────── FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ──── USER ftpuser ────▶ FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ◀─── 331 Password ───── FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ──── PASS ftppass123 ▶ FTP (172.50.2.15:21)
CLIENT (172.50.2.100) ◀─── 230 Login OK ───── FTP (172.50.2.15:21)
```

### SMTP / Email Akışı
```
CLIENT (172.50.2.100) ──── EHLO ──────────────────▶ SMTP (172.50.2.16:1025)
CLIENT (172.50.2.100) ──── MAIL FROM:<kullanici@shark-tank.local> ──▶ SMTP
CLIENT (172.50.2.100) ──── RCPT TO:<destek@shark-tank.local> ──▶ SMTP
CLIENT (172.50.2.100) ──── DATA (email body) ──────▶ SMTP
CLIENT (172.50.2.100) ◀─── 250 OK ────────────────── SMTP
```

### POP3 / IMAP Akışı
```
CLIENT (172.50.2.100) ──── USER kullanici ──────────▶ IMAP (172.50.2.18:110)
CLIENT (172.50.2.100) ──── PASS secret123 ─────────▶ IMAP
CLIENT (172.50.2.100) ──── STAT / LIST / RETR ─────▶ IMAP
CLIENT (172.50.2.100) ◀─── +OK messages ──────────── IMAP

CLIENT (172.50.2.100) ──── LOGIN kullanici ─────────▶ IMAP (172.50.2.18:143)
CLIENT (172.50.2.100) ──── SELECT INBOX ───────────▶ IMAP (IMAP)
CLIENT (172.50.2.100) ──── FETCH 1 BODY ───────────▶ IMAP
```

### SIP / VoIP Akışı
```
CLIENT (172.50.2.100) ──── REGISTER 1000 ──────────▶ VOIP (172.50.2.22:5060/UDP)
CLIENT (172.50.2.100) ◀─── 200 OK ────────────────── VOIP
CLIENT (172.50.2.100) ──── INVITE 1000→1001 ───────▶ VOIP
CLIENT (172.50.2.100) ◀─── 180 Ringing / 200 OK ──── VOIP
CLIENT (172.50.2.100) ════ RTP stream (ses) ═══════▶ VOIP
CLIENT (172.50.2.100) ──── BYE ─────────────────────▶ VOIP
```

### UDP Echo Akışı
```
CLIENT (172.50.2.100) ──── UDP "test" ─────────────▶ UDP ECHO (172.50.2.17:9090)
CLIENT (172.50.2.100) ◀─── UDP "test" (echo) ─────── UDP ECHO (172.50.2.17:9090)
CLIENT (172.50.2.100) ──── UDP kapalı port ────────▶ UDP ECHO (172.50.2.17:9999)
CLIENT (172.50.2.100) ◀─── ICMP Port Unreachable ─── (172.50.2.17)
```

### DHCP DORA Süreci
```
DHCP CLIENT (dhcp-client) ──── DHCP Discover (broadcast) ─▶ DHCP SERVER (172.50.9.2:67)
DHCP CLIENT (dhcp-client) ◀─── DHCP Offer (IP teklifi) ────── DHCP SERVER
DHCP CLIENT (dhcp-client) ──── DHCP Request (kabul) ────────▶ DHCP SERVER
DHCP CLIENT (dhcp-client) ◀─── DHCP ACK (onay) ─────────────── DHCP SERVER
```

### Attacker Akışı (Port Scan)
```
ATTACKER (172.50.2.200) ──── SYN :80 ───────▶ WEB (172.50.2.10)
ATTACKER (172.50.2.200) ◀─── SYN-ACK ──────── WEB (172.50.2.10)   [OPEN]
ATTACKER (172.50.2.200) ──── SYN :22 ───────▶ WEB (172.50.2.10)
ATTACKER (172.50.2.200) ◀─── RST ──────────── WEB (172.50.2.10)   [CLOSED]
ATTACKER (172.50.2.200) ──── SYN :443 ──────▶ WEB (172.50.2.10)
ATTACKER (172.50.2.200) ◀─── RST ──────────── WEB (172.50.2.10)   [CLOSED]
```

## Port Matrisi

| Servis | 21 | 53 | 67 | 80 | 110 | 143 | 443 | 587 | 1025 | 5060 | 8080 | 9090 |
|--------|----|----|----|----|-----|-----|-----|-----|------|------|------|------|
| Web (.10) | | | | **OPEN** | | | | | | | | |
| DNS (.11) | | **OPEN** | | | | | | | | | | |
| DHCP Server (.9.2) | | | **OPEN** | | | | | | | | | |
| HTTPS (.13) | | | | | | | **OPEN** | | | | | |
| FTP (.15) | **OPEN** | | | | | | | | | | | |
| SMTP (.16) | | | | | | | | | **OPEN** | | | |
| UDP Echo (.17) | | | | | | | | | | | | **OPEN** |
| IMAP (.18) | | | | | **OPEN** | **OPEN** | | **OPEN** | | | | |
| VoIP (.22) | | | | | | | | | | **OPEN** | | |
| TCP Echo (.12) | | | | | | | | | | | **OPEN** | |
