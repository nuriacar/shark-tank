# Modül 24: Sınav Pratiği

**Neden?** Sınav günü. 60 dakikan var. Karışık pcap'te port scan, SQL injection, HTTP credential capture, DNS tunneling, FTP brute force, C2 beaconing: hepsi aynı dosyada. Tüm protokolleri birleştirip kill chain'i oluşturmak sınavın ve gerçek hayatın ta kendisidir. Bu modül: sınav formatında tüm becerileri uygulamak.

**Görev:** Karışık pcap'i analiz et. Tüm protokolleri tanı, anomalileri bul, soruları cevapla.

**Öğrenim Hedefleri:**
- Karışık protokol trafiğinde (HTTP, DNS, TLS, ICMP, FTP, TCP) hızlıca gezinebilmek
- Port scan, SYN flood, credential capture, brute force gibi saldırıları tek pcap'te tespit edebilmek
- Protocol Hierarchy, Conversations, IO Graph gibi istatistik araçlarını etkin kullanabilmek
- Tüm Wireshark becerilerini 60 dakika içinde sınav formatında uygulayabilmek
- Saldırganın kill chain'ini oluşturup adımları kronolojik sıraya koyabilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **pcap** | Packet Capture: ağ trafiğinin yakalanıp kaydedildiği dosya formatı. Bir pcap dosyası, ağ kartından geçen her paketin kopyasını alır ve zaman damgasıyla birlikte saklar. Güvenlik analistleri bir olayı incelerken "ağda ne oldu?" sorusunun cevabını pcap dosyasında arar. Wireshark ile açıldığında her paket katman katman (Ethernet → IP → TCP → uygulama) görüntülenebilir. Ders boyunca `shared/pcaps/` klasöründeki pcap dosyaları üzerinde çalışacaksınız. |
| **display filter** | Wireshark'ta yakalanan paketler arasında filtreleme yapmak için kullanılan sistem. Yakalama bittikten sonra çalışır: paketleri silmez, yalnızca belirttiğin kritere uymayanları gizler. Display filter yazımı Wireshark'a özgü bir syntax kullanır: `ip.addr == 172.50.2.10`, `tcp.port == 80`, `http.request.method == "GET"` gibi. Birden fazla koşul `&&` (ve), `||` (veya), `!` (değil) operatörleriyle birleştirilebilir. WCNA sınavında en çok test edilen filtreleme türüdür. |
| **Protocol Hierarchy** | Wireshark ve tshark'ın bir pcap içindeki protokolleri katman katman özetleyen istatistik aracı. Her protokolün pcap içindeki paket sayısını ve yüzde oranını gösterir: örneğin "%85 TCP, %60 HTTP, %20 DNS, %15 ARP" gibi. Bu özet, pcap'in genel içeriğini hızlıca anlamak için ilk bakılan araçtır. GUI'de `Statistics > Protocol Hierarchy`, tshark'ta `-q -z io,phs` komutuyla kullanılır. |
| **Conversations** | Wireshark'ın bir pcap içindeki tüm iletişim çiftlerini (conversation) listeleyen istatistik aracı. `Statistics → Conversations` menüsünden açılır. Her satır iki cihaz arasındaki trafiği özetler: kaynak ve hedef IP, port, paket sayısı, byte sayısı, süre. TCP, UDP ve IP seviyesinde ayrı ayrı gösterilir. Baseline analizinde hangi IP çiftlerinin normalde ne kadar veri transfer ettiğini belirlemek için kullanılır. Beklenmeyen yeni conversation'lar (bilinmeyen bir dış IP ile çok veri) veri sızdırma veya C2 bağlantısı gösterebilir. |
| **IO Graph** | Wireshark'ın tüm trafiğin zaman içindeki dağılımını gösteren genel amaçlı grafik aracı. `Statistics → IO Graph` menüsünden açılır. X ekseni zamanı, Y ekseni paket/saniye veya byte/saniyeyi gösterir. Belirli zaman aralıklarında (interval) trafik yoğunluğunu görselleştirir: ani spike'lar DDoS veya veri sızdırma, düz ve düşük seviye normal trafiği gösterir. Display filter ile farklı protokolleri veya IP'leri ayrı renklerde çizdirebilirsiniz. Sınavda "hangi grafik toplam trafik yoğunluğunu gösterir?" sorusunun cevabı IO Graph'tir. |
| **Expert Information** | Wireshark'ın pcap içindeki anormallikleri ve sorunları otomatik olarak tespit edip listelediği panel. `View > Expert Information` (Ctrl+Alt+Shift+E) menüsünden açılır. Sorunları dört ciddiyet seviyesinde gruplar: Error (kırmızı), Warn (sarı), Note (mavi), Chat (yeşil). Bir analist pcap'i açtığında ilk bakması gereken yerlerden biridir; çünkü retransmission, duplicate ACK, zero window, HTTP 404 gibi sorunları paket tek tek aranmadan özet olarak gösterir. |

## Teori

Gerçek bir sınav veya olay müdahalesinde karşınıza **tek bir protokolün** pcap'i çıkmaz. Saldırganlar:

- **HTTP** ile C2 (Command & Control) haberleşmesi yapar
- **DNS** ile veri sızdırır (DNS tunneling)
- **FTP** ile çalınan verileri dışarı aktarır
- **ICMP** ile keşif yapar (ping sweep, covert channels)
- **TLS** ile trafiği şifreleyip gizler

Bu modül, tüm bu protokolleri aynı anda analiz etme becerinizi ölçer.

### Anahtar Kavramlar:

| Kavram | Anlamı |
|--------|--------|
| **Protocol Hierarchy** | Hangi protokoller var? Oranları nedir? |
| **Conversations** | Hangi IP'ler hangi portlardan konuşuyor? |
| **Time Delta** | Paketler arası süre: saldırı desenlerini yakala |
| **Anomali** | Normalden sapan her şey (yanlış port, hatalı paket, scan) |
| **Follow TCP Stream** | Bir TCP akışının tam içeriğini gör |

## Genel Bakış

Bu modül, sınavda karşılaşacağınız türdeki soruları pratik etmeniz içindir.
Karışık trafik içeren bir pcap dosyası üzerinde çalışacaksınız.

> **İstihbarat İşaretleri, Gerçek dünyada saldırılar tek protokolle gelmez:**
>
> - Aynı pcap'de HTTP + DNS + FTP + ICMP = **Karışık senaryo** (gerçek incident)
> - Statistics > Protocol Hierarchy ile genel resmi gör
> - Statistics > Conversations ile **kim kimle konuşuyor** tespit et
> - `ip.addr == 172.50.2.200` ile saldırganın tüm aktivitesini filtrele
> - **Dikkat:** Saldırganın davranış kalıpları tutarlı mı? Bir APT bu kadar mı "gürültülü" olur?

## Hazırlık

```bash
# Karışık trafik oluştur:
./scripts/generate-traffic.sh mixed

# Wireshark ile aç:
# macOS: open -a Wireshark shared/pcaps/module-24-exam-practice.pcap
# Linux: wireshark shared/pcaps/module-24-exam-practice.pcap &
# Windows: start wireshark shared/pcaps/module-24-exam-practice.pcap
```

---

## SENARYO 1: Genel Trafik Analizi

### Soru 1: Kaç farklı protokol var?

**İpucu:** Wireshark'ta **Statistics > Protocol Hierarchy** menüsünü kullan.

```
Beklenen sonuç:
- Ethernet
- Internet Protocol (IP)
  - TCP
    - HTTP
    - TLS
  - UDP
    - DNS
  - ICMP
```

### Soru 2: Ağdaki IP adreslerini listele

**İpucu:** **Statistics > Endpoints > IPv4**

```
Beklenen:
- 172.50.2.100  (Client)
- 172.50.2.10   (Web)
- 172.50.2.11   (DNS)
- 172.50.2.12   (TCP Echo)
- 172.50.2.13   (HTTPS)
- 172.50.2.14   (ICMP Target)
- 172.50.2.15   (FTP)
- 172.50.2.200  (Attacker)
```

### Soru 3: Hangi IP en çok trafik üretti?

**İpucu:** **Statistics > Conversations > IPv4** -> Bytes sütununa göre sırala.

---

## SENARYO 2: HTTP Forensics

### Soru 4: Admin kullanıcısının şifresi nedir?

```
# Filtre:
http.request.method == "POST"
```

POST body'sindeki `password` alanını bul.

**Beklenen:** `secret123`

### Soru 5: Hangi web sayfaları ziyaret edildi?

```
# Filtre:
http.request
```

Her GET/POST isteğinin URI'sini listele.

### Soru 6: HTTP response'lardan hangi dosya/dosyalar export edilebilir?

**İpucu:** **File > Export Objects > HTTP**

---

## SENARYO 3: DNS Analizi

### Soru 7: Hangi domainler sorgulandı?

```
# Filtre:
dns.flags.response == 0
```

Her DNS query'nin `Query Name` alanını not al.

### Soru 8: web.shark-tank.local hangi IP'ye çözümlendi?

```
# Filtre:
dns.qry.name == "web.shark-tank.local" && dns.flags.response == 1
```

Answer RR'deki IP adresini bul.

**Beklenen:** `172.50.2.10`

### Soru 9: NXDomain (bulunamayan) domain var mı?

```
# Filtre:
dns.flags.rcode == 3
```

---

## SENARYO 4: TLS Analizi

### Soru 10: TLS handshake'de hangi cipher suite seçildi?

```
# Filtre:
tls.handshake.type == 2    # ServerHello
```

`Cipher Suite` alanını bul.

### Soru 11: TLS sertifikasını kim verdi (issuer)?

```
# Filtre:
tls.handshake.type == 11   # Certificate
```

Certificate > issuer alanını incele.

**Beklenen:** `O=Shark-Tank, OU=Network Analysis Lab`

### Soru 12: Şifrelenmiş veri okunabilir mi?

```
# Filtre:
tls.record.content_type == 23
```

Application Data paketlerini incele -> hex veri görünür, ama anlamlı değil.

---

## SENARYO 5: ICMP Analizi

### Soru 13: Kaç ping başarılı oldu?

```
# Filtre:
icmp.type == 0    # Echo Reply
```

Başarılı ping sayısı = Reply sayısı.

### Soru 14: RTT (Round Trip Time) ortalama kaç ms?

Her Request-Reply çifti arasındaki zaman farkını hesapla.

---

## SENARYO 6: Güvenlik Analizi (Port Scan)

### Soru 15: Port scan hangi IP'den geldi?

```
# Filtre:
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Tek bir IP'den çok fazla farklı porta SYN gönderildiğini göreceksin.

**Beklenen:** `172.50.2.200` (Attacker)

### Soru 16: Hangi portlar AÇIK bulundu?

AÇIK portlar: SYN'e SYN-ACK cevap geldi.
```
tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.srcport < 1024
```

### Soru 17: Hangi portlar KAPALI?

KAPALI portlar: SYN'e RST cevap geldi.
```
tcp.flags.reset == 1
```

### Soru 18: SYN flood simulasyonunu bul

```
# Filtre:
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 172.50.2.200
```

Kısa sürede çok fazla SYN paketi = SYN flood.

**Kaç SYN paketi gönderildi?** Say.

### Soru 19: IO Graph ile SYN Flood'u Görselleştir

1. **Statistics > IO Graph**
2. X ekseni: Zaman, Y ekseni: Packets/Tick
3. **Filter** alanına `tcp.flags.syn == 1 && tcp.flags.ack == 0` yaz
4. SYN flood'un oluşturduğu dikey pik'i görsel olarak tespit et
5. Normal trafik ile saldırı trafiği arasındaki farkı IO Graph üzerinde gözlemle

> **SINAV İPUCU:** IO Graph, SYN flood gibi volumetrik saldırıları görselleştirmek için en hızlı araçtır. Normal trafik düşük seyrederken, saldırı anında grafikte anlık bir "tepe" (spike) görürsün.

---

## SENARYO 7: FTP Analizi

Bu pcap'te FTP sunucusuna (172.50.2.15) başarılı bir giriş var.

### Soru 20: FTP kullanıcı adı ve şifre nedir?

```
# Filtre:
ftp.request.command == "USER" || ftp.request.command == "PASS"
```

FTP, tıpkı HTTP gibi şifresizdir. Kullanıcı adı ve şifre açıkça görünür.

**Beklenen:** `ftpuser / ftppass123`

### Soru 21: Başarılı giriş sonrası hangi komutlar gönderildi?

```
# Tüm FTP komutları:
ftp.request.command
```

### Soru 22: FTP hangi portları kullanıyor?

- **Kontrol (komut):** TCP 21
- **Veri (data):** TCP 20 veya rastgele yüksek port (PASV mode)

> **SINAV İPUCU:** FTP, HTTP gibi cleartext protokoldür. Wireshark ile FTP şifrelerini okuyabilirsin. FTP'de iki kanal vardır: Control (21) ve Data (20/PASV).

---

## SENARYO 8: Kill Chain Oluşturma

Tüm senaryoları birleştirip saldırganın adımlarını kronolojik sıraya koy:

### Aşamalar:

| Aşama | Bulgu | Filter/IP |
|-------|-------|-----------|
| **1. Reconnaissance** | Port scan | SYN → farklı portlara |
| **2. Weaponization** | (Bu pcap'te yok: saldırı araçları önceden hazırlanır) |: |
| **3. Delivery** | HTTP POST /auth + FTP giriş | curl istekleri |
| **4. Exploitation** | (Bu pcap'te yok: zafiyet sömürme) |: |
| **5. Installation** | SYN flood (DoS) | Aynı porta çok SYN |
| **6. C2** | (Bu pcap'te yok: düzenli beaconing) |: |
| **7. Exfiltration** | Credential sızıntısı (HTTP) | POST body: secret123 |

### Ne Yapmalısın?
1. **Statistics > Conversations > IPv4** ile tüm konuşmaları listele
2. Zaman sütununa göre sırala: hangi paket önce geldi?
3. Attacker (172.50.2.200) ile Client (172.50.2.100) aktivitelerini ayır
4. Kronolojik sırayı belirle: Scan mı önce, flood mu önce, FTP mi önce?
5. Her aşama için kanıt paket numarasını not et

### Statistics > Flow Graph ile Kill Chain Timeline:

**Flow Graph**, tüm trafiğin görsel zaman çizelgesini gösterir: kill chain oluşturmak için en hızlı araçtır.

1. **Statistics > Flow Graph** menüsünü aç
2. Her bağlantı ayrı bir satırda, paketler zaman çizelgesinde gösterilir
3. Attacker (172.50.2.200) satırını bul: hangi paketlerden başlıyor?
4. Saldırı aşamalarını çizelgede işaretle:
   - İlk SYN paketleri = Reconnaissance (port scan)
   - HTTP istekleri = Delivery (credential deneme)
   - FTP bağlantısı = Delivery (veri erişimi)
   - SYN flood = Installation/DoS
5. **Bars** yerine **Default** görünümü dene: her protokol farklı renkte

> **SINAV İPUCU:** Flow Graph, "saldırgan ne zaman ne yaptı?" sorusunun görsel cevabıdır. Conversations tablosu + Flow Graph birlikte kullanıldığında kill chain kronolojisi tam olarak ortaya çıkar.

> **SINAV İPUCU:** Gerçek bir incident response'ta kill chain oluşturmak, saldırganın ne yaptığını anlamanın en etkili yoludur. Wireshark'ta zaman damgalarını takip ederek her adımı sıralayabilirsin.

---

## SENARYO 9: TCP Akış Analizi

### Soru 23: TCP echo sunucusuna gönderilen mesaj neydi?

```
# Filtre:
tcp.dstport == 8080 && tcp.payload
```

Payload alanını incele.

**Beklenen:** `test`

### Soru 24: 3-way handshake örneği bul

```
# Filtre:
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Her SYN için sonraki SYN-ACK ve ACK paketlerini bul.

---

## BONUS: Wireshark İstatistik Araçları

Sınavda işinize yarayacak istatistik menüleri:

| Menü | Ne İşe Yarar |
|------|-------------|
| **Statistics > Summary** | Genel özet (toplam paket, süre, vb.) |
| **Statistics > Protocol Hierarchy** | Protokol dağılımı |
| **Statistics > Conversations** | IP/TCP/UDP konuşmaları |
| **Statistics > Endpoints** | IP/MAC endpoint'leri |
| **Statistics > HTTP > Requests** | HTTP istek listesi |
| **Statistics > DNS** | DNS sorgu istatistikleri |
| **Statistics > Flow Graph** | Görsel akış grafikleri |
| **Statistics > TCP Stream Graphs** | TCP performans grafikleri |
| **Statistics > IO Graph** | Zaman bazlı trafik yoğunluğu, saldırı tespiti |

---

## Sınavda Zaman Yönetimi

1. **Önce pcap'i aç ve genel bakış at** (Protocol Hierarchy, Conversations)
2. **Soruyu oku -> uygun filtre yaz**
3. **Follow TCP Stream** ile tam oturumları oku
4. **Export Objects** ile dosyaları kurtar
5. **Statistics** menüleriyle genel istatistikleri al
6. **Zamanın varsa** her soruyu ikinci kez kontrol et

---

## Sınav Soruları (Çöz)

1. pcap'de kaç farklı **protokol** tespit ediliyor?
2. Hangi IP adresleri trafiğe katılıyor?
3. En çok trafik üreten IP hangisi? (**Statistics > Endpoints**)
4. HTTP POST body'sinde hangi credential var?
5. HTTP ile hangi endpoint'lere istek yapılmış?
6. HTTP response'dan hangi veriler export edilebilir?
7. DNS'de hangi domain'ler sorgulanıyor?
8. web.shark-tank.local hangi IP'ye çözümleniyor?
9. DNS'de hata alan (NXDOMAIN) sorgu var mı?
10. TLS handshake'de hangi TLS sürümü kullanılıyor?
11. Sertifikanın **Issuer** bilgisi nedir?
12. TLS Application Data içeriği görülebilir mi?
13. Toplam kaç ICMP Echo Reply var?
14. En düşük RTT değeri nedir?
15. Ping atan IP hangisi?
16. Hangi portlar açık (SYN-ACK dönen)?
17. Hangi portlar kapalı (RST dönen)?
18. Kaç SYN paketi gönderilmiş?
19. IO Graph ile SYN flood'u görselleştir: grafikte ne görüyorsun?
20. FTP kullanıcı adı ve şifresi nedir?
21. Başarılı FTP giriş sonrası hangi komutlar gönderildi?
22. FTP hangi portları kullanıyor?
23. TCP echo akışında hangi metin gönderilmiş?
24. TCP handshake'de sıralama nasıl?

Cevaplar aşağıda:

**Tebrikler!** Tüm modülleri tamamladınız. Başarılar dileriz!

<details markdown="block">
<summary>Cevapları Göster</summary>

**SENARYO 1:**
1. **TCP, UDP, ICMP, ARP: Protocol Hierarchy'de TCP altında HTTP/TLS, UDP altında DNS görülür. FTP de TCP üzerinde gelir.**
2. **172.50.2.10, .11, .12, .13, .14, .15, .100, .200**
3. **172.50.2.100 (Client) veya 172.50.2.200 (Attacker): Statistics > Endpoints ile bulunur**

**SENARYO 2:**
4. **secret123 (POST /auth body: username=admin&password=secret123)**
5. **/ (ana sayfa), /api/data, /auth**
6. **HTTP Object Export ile JSON response'lar**

**SENARYO 3:**
7. **web.shark-tank.local, secure.shark-tank.local, google.com, nonexistent.shark-tank.local**
8. **172.50.2.10**
9. **Evet, nonexistent.shark-tank.local**

**SENARYO 4:**
10. **TLS handshake > ServerHello içinde görülür**
11. **O=Shark-Tank, OU=Network Analysis Lab (self-signed)**
12. **Hayır, Application Data şifrelidir**

**SENARYO 5:**
13. **Ping sayısı değişkendir. `icmp.type == 0` filtresiyle Reply paketlerini sayın.**
14. **Değişkendir. RTT sütununu kontrol edin.**
15. **172.50.2.100 (Client): ICMP Echo Request'ler bu IP'den gönderildi**

**SENARYO 6:**
16. **80 (HTTP), SYN-ACK gelen portlar**
17. **RST gelen veya yanıt vermeyen portlar**
18. **SYN sayısı değişkendir. `ip.src==172.50.2.200 && tcp.flags.syn==1 && tcp.flags.ack==0` filtresiyle sayın.**
19. **IO Graph'da SYN flood anında dikey bir pik (spike) görülür. Normal trafik düşük seyrederken saldırı anında ani yükseliş olur.**

**SENARYO 7 (FTP):**
20. **ftpuser / ftppass123: FTP cleartext olduğu için Wireshark'ta açıkça görünür**
21. **SYST, PWD, PASV, LIST gibi komutlar: `ftp.request.command` filtresiyle görülür**
22. **Kontrol: TCP 21, Veri: PASV response'unda verilen yüksek port (21100-21110 arası)**

**SENARYO 8 (Kill Chain):**
> **Reconnaissance (port scan), Delivery (HTTP + FTP), Installation (SYN flood), Exfiltration (credential sızıntısı). Weaponization, Exploitation, C2 bu pcap'te yok.**

**SENARYO 9:**
23. **"test" (echo "test" | nc 172.50.2.12 8080)**
24. **Herhangi bir TCP bağlantısında SYN → SYN-ACK → ACK görülür**

</details>

---

**Önceki Modül:** [Baseline Analizi](../module-23-baseline/module-23-baseline.md)

**Sonraki Modül:** [Ağ Forensics](../module-25-forensics/module-25-forensics.md)