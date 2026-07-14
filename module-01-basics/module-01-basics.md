# Modül 01: Wireshark Temelleri

**Neden?** SOC L1 stajyeri olarak ilk günün. Ekibin elinde bir pcap var: "ağda bir şeyler dönüyor" deniyor. Nereye bakacağını bilmiyorsun. Wireshark, ağ saldırılarını tespit etmenin en temel aracıdır. Port scanning, ARP spoofing, DNS tunneling, C2 beaconing: her saldırı türü paket seviyesinde iz bırakır. Wireshark olmadan bu izleri görmek imkansızdır. Bu modül: Wireshark'ı açıp ilk pcap'ini analiz etmek.

**Görev:** Pcap dosyasını Wireshark'ta aç. Arayüzü tanı.

**Öğrenim Hedefleri:**
- Wireshark arayüzünü (3 panel, araç çubuğu, durum çubuğu) tanımak
- Pcap dosyasını açıp paket katmanlarını okuyabilmek
- Renk kodlarının anlamını kavramak
- Follow TCP Stream ile bir konuşmayı takip edebilmek
- Temel display filter yazabilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **pcap** | Packet Capture: ağ trafiğinin yakalanıp kaydedildiği dosya formatı. Bir pcap dosyası, ağ kartından geçen her paketin kopyasını alır ve zaman damgasıyla birlikte saklar. Güvenlik analistleri bir olayı incelerken "ağda ne oldu?" sorusunun cevabını pcap dosyasında arar. Wireshark ile açıldığında her paket katman katman (Ethernet → IP → TCP → uygulama) görüntülenebilir. Ders boyunca `shared/pcaps/` klasöründeki pcap dosyaları üzerinde çalışacaksınız. |
| **paket** | Ağ üzerinden gönderilen temel veri birimi. Her paket, bir zarf gibi hem adres bilgisi (kaynak IP, hedef IP, port numaraları) hem de içerik (kullanıcı verisi) taşır. Ağ protokolleri katmanlı olduğu için, bir paket içinde başka bir protokol gömülü olabilir: Ethernet çerçevesinin içinde IP paketi, onun içinde TCP segmenti, onun içinde de HTTP isteği bulunur. Wireshark'ta her paket paket listesinde tek bir satır olarak görünür ve tıklandığında detayları katman katman açılır. |
| **frame** | Bir paketin fiziksel ağ (Layer 1–2) üzerindeki temsilidir. Wireshark her paketin en üstünde "Frame N" satırını gösterir; bu satırda paketin toplam boyutu, yakalandığı zaman ve fiziksel arayüz bilgisi yer alır. Pratikte "frame" ve "paket" kavramları sıklıkla birbirinin yerine kullanılır, ancak teknik olarak frame alt katmanı (Ethernet), paket ise üst katmanı (IP) ifade eder. |
| **katman (layer)** | Ağ protokollerinin iç içe geçmiş hiyerarşik yapısı. Her katman belirli bir görevden sorumludur: Ethernet (Layer 2) fiziksel adresleme (MAC), IP (Layer 3) mantıksal adresleme, TCP/UDP (Layer 4) taşıma, HTTP/DNS (Layer 7) uygulama verisi. Bu model sayesinde farklı üreticilerin cihazları ve farklı ağ teknolojileri birbiriyle uyumlu çalışabilir. Wireshark paket detaylarında her katmanı ayrı bir bölüm olarak gösterir; `>` işaretine tıklayarak açıp kapatabilirsiniz. |
| **MAC adresi** | Media Access Control: bir ağ kartının donanımsal fiziksel adresi. 6 byte (48 bit) uzunluğundadır ve `aa:bb:cc:dd:ee:ff` biçiminde yazılır. Her ağ kartı fabrikadan çıkarken benzersiz bir MAC adresi alır; theoretically değişmez, ama işletim sistemi seviyesinde geçici olarak değiştirilebilir. Ethernet (Layer 2) trafiği MAC adresleriyle çalışır: aynı yerel ağdaki iki cihaz birbirlerini MAC adresleriyle bulur ve veri gönderir. |
| **IP adresi** | Internet Protocol adresi: bir cihazın ağ üzerindeki mantıksal adresi. IPv4'te 32 bit (örn. `172.50.2.10`), IPv6'da 128 bit uzunluğundadır. MAC adresinden farklı olarak kalıcı değildir; ağa her bağlanışta DHCP tarafından otomatik atanabilir veya elle değiştirilebilir. Router'lar paketleri hedef IP adresine bakarak doğru yönüne iletir. |
| **port** | Bir cihaz üzerindeki uygulama girişi. 16 bitlik bir numaradır (0–65535) ve her ağ servisi belirli bir port numarasını kullanır: HTTP 80, HTTPS 443, DNS 53, FTP 21 gibi. Bir paket cihaza ulaştığında, port numarasına bakarak hangi uygulamaya teslim edileceği belirlenir. 0–1023 arası "well-known" (iyi bilinen) portlarıdır ve standart servislere ayrılmıştır. |
| **TCP** | Transmission Control Protocol: internetin güvenilir ve sıralı veri iletimini sağlayan protokol. Veriyi göndermeden önce alıcıyla bağlantı kurar (3-way handshake), gönderdiği her paket için onay (ACK) bekler ve onay gelmeyen paketleri yeniden gönderir (retransmission). Bu mekanizmalar sayesinde veri kaybı olmadan ve gönderim sırasında bozulmadan teslim edilir. Web (HTTP), email (SMTP), dosya transferi (FTP) gibi kritik işlemlerin tamamı TCP üzerinden çalışır. Bağlantı kurma ve onay bekleme yükü nedeniyle UDP'den yavaştır, ama güvenilirlik gerektiğinde tek seçenektir. |
| **UDP** | User Datagram Protocol: bağlantı kurmadan doğrudan veri gönderen hızlı protokol. Handshake yoktur, onay (ACK) beklenmez, kaybolan paketler yeniden gönderilmez. Bu sayede TCP'den çok daha hızlı ve düşük gecikmeli çalışır, ancak güvenilirlik garantisi yoktur. DNS sorguları, video streaming, VoIP ve çevrimiçi oyunlar gibi hızın güvenilirlikten önemli olduğu uygulamalar UDP kullanır. Başlığı (header) sadece 8 byte'tır; TCP'nin minimum 20 byte'ına kıyasla çok daha hafiftir. |
| **HTTP** | HyperText Transfer Protocol: web tarayıcıları ile web sunucuları arasındaki iletişim protokolü. İstemci (browser) bir istek (request) gönderir, sunucu bir yanıt (response) döner. Tüm içerik düz metin (cleartext) olarak iletilir: hiçbir şifreleme yoktur. Bu yüzden Wireshark ile HTTP trafiğini izleyen biri şifreleri, cookie'leri, form verilerini dahil her şeyi açıkça görebilir. Port 80 kullanır. HTTPS, HTTP'in TLS ile şifrelenmiş halidir (port 443). |
| **DNS** | Domain Name System: insan tarafından okunabilir alan adlarını (örn. `web.shark-tank.local`) IP adreslerine (örn. `172.50.2.10`) çeviren sistem. Cihazlar birbiriyle IP adresleriyle iletişim kurar, ama insanlar alan adlarını hatırlar; DNS bu çeviriyi yapar. Port 53 kullanır ve normalde UDP üzerinden çalışır. Güvenlik açısından DNS, veri sızdırmak (DNS tunneling) veya kullanıcıları sahte sitelere yönlendirmek (DNS poisoning) için istismar edilebilen bir protokoldür. |
| **ICMP** | Internet Control Message Protocol: ağ tanılama ve hata bildirimi için kullanılan protokol. Port kullanmaz; Layer 3'te (IP katmanı) doğrudan çalışır, bu yüzden "Layer 3.5" olarak da adlandırılır. En bilinen kullanımı ping komutudur: bir cihaza "orada mısın?" diye sorar (Echo Request), karşı taraf "evet, buradayım" diye yanıtlar (Echo Reply). traceroute aracı da ICMP kullanarak bir paketin geçtiği router'ları adım adım tespit eder. Güvenlik duvarları ICMP trafiğine genellikle izin verir; bu yüzden saldırganlar ICMP paketlerinin içine veri gizleyerek güvenlik duvarını aşabilir (ICMP tunneling). |
| **ARP** | Address Resolution Protocol: aynı yerel ağ (LAN) üzerinde, bilinen bir IP adresine karşılık gelen MAC adresini bulmak için kullanılan protokol. Bir cihaz başka bir cihazla iletişim kurmadan önce onun MAC adresini bilmelidir, çünkü Ethernet çerçeveleri MAC adresleriyle teslim edilir. ARP, "Bu IP adresi kimin?" diye tüm ağa sorar (broadcast) ve ilgili cihaz "Benim, MAC adresim şu" diye yanıt verir. Her cihaz bu eşleşmeleri ARP cache adı verilen geçici bir tabloda saklar. Saldırganlar sahte ARP yanıtları göndererek trafiği kendilerine yönlendirebilir (ARP spoofing). |
| **display filter** | Wireshark'ta yakalanan paketler arasında filtreleme yapmak için kullanılan sistem. Yakalama bittikten sonra çalışır: paketleri silmez, yalnızca belirttiğin kritere uymayanları gizler. Display filter yazımı Wireshark'a özgü bir syntax kullanır: `ip.addr == 172.50.2.10`, `tcp.port == 80`, `http.request.method == "GET"` gibi. Birden fazla koşul `&&` (ve), `||` (veya), `!` (değil) operatörleriyle birleştirilebilir. WCNA sınavında en çok test edilen filtreleme türüdür. |
| **Follow TCP Stream** | Wireshark'ın bir TCP bağlantısındaki tüm veriyi baştan sona tek pencerede gösteren özelliği. Bir HTTP oturumunu, bir FTP transferini veya bir email gönderimini tam olarak görmek için kullanılır. Paket listesindeki herhangi bir pakete sağ tıklayıp "Follow > TCP Stream" seçilerek açılır. İstemcinin gönderdiği veri (request) ve sunucunun yanıtı (response) farklı renklerle ayrılarak görüntülenir. Sınavda credential sızıntısı, SQL injection payload'ı veya email içeriği gibi verileri hızlıca okumak için en kullanışlı araçtır. |
| **retransmission** | TCP'de onay (ACK) gelmeyen bir paketin kaynak tarafından yeniden gönderilmesi. TCP güvenilir bir protokoldür: her gönderdiği paket için bir zamanlayıcı (timer) başlatır ve belirli süre içinde ACK gelmezse paketi tekrar gönderir. Wireshark retransmission paketlerini siyah renkle işaretler. Çok sayıda retransmission, ağ tıkanıklığı, kablosuz sinyal sorunu veya kasıtlı saldırı (ACK flood) gösterebilir. |

## Teori (Kısa Özet)

Wireshark, ağ üzerindeki paketleri yakalayıp analiz eden bir araçtır. Her paket **katmanlı** bir yapısıdadır:

```
Frame (Layer 1 - Fiziksel)     -> Paketin kablo üzerindeki hali
  Ethernet (Layer 2 - Veri Bağı) -> MAC adresleri
    IP (Layer 3 - Ağ)            -> IP adresleri
      TCP/UDP (Layer 4 - Taşıma) -> Port numaraları
        HTTP/DNS/... (Layer 7)   -> Uygulama verisi
```

> **İstihbarat İşaretleri, Bir güvenlik analisti bunları arar:**
>
> - Paket listesinde **siyah satırlar** = TCP retransmission (bağlantı sorunu)
> - **Kırmızı** paketler beklenmeyen yerde = ICMP anomaly
> - **Mor** paketler data transferi olmadan = port scan olabilir
> - Aynı IP'den sürekli farklı portlara bağlantı = **kesinlikle şüpheli**

## Hazırlık

```bash
./scripts/generate-traffic.sh basics
```

Pcap'i Wireshark'ta aç:
```bash
make open FILE=shared/pcaps/module-01-basics.pcap
```

## Adım 1: Wireshark'i Aç

 1. Wireshark'i kur:
    ```
    # macOS
    brew install --cask wireshark
    
    # Ubuntu / Debian
    sudo apt-get install wireshark
    
    # Windows
    # https://www.wireshark.org/download.html adresinden indir
    ```
 2. Wireshark uygulamasını aç

## Adım 2: Capture Başlat (Ortam Kurulduktan Sonra)

> **ÖNEMLİ:** Önce `scripts/start.sh` ile Docker ortamını başlat.

1. Wireshark'ta **hangi arayüzü dinleyeceğini** seç (üst kısmında listelenir):
   - `lo0` (macOS) / `lo` (Linux) - loopback
   - `en0` (macOS) / `eth0` / `wlan0` (Linux) - ağ arayüzü
   - Docker arayüzleri (varsa)

2. **macOS + Docker Desktop** için en pratik yöntem:
   - Docker ağdaki pcap dosyasını Wireshark ile açmak
   - `shared/pcaps/` klasöründeki `.pcap` dosyalarını kullan

## Adım 3: pcap Dosyası ile Çalışma

1. **File > Open** ile `shared/pcaps/` altındaki bir pcap dosyasını aç
2. Veya terminal'den: `wireshark shared/pcaps/module-01-basics.pcap`

## Adım 4: Wireshark Arayüzünü Tanı

Wireshark ekranı **3 ana panel**den oluşur:

```
+------------------------------------------------------+
| Paket Listesi (Packet List)                          |
|  No | Time      | Source      | Destination | Proto  |
|  1  | 0.000     | 172.50.2.100| 172.50.2.10 | HTTP   |
|  2  | 0.001     | 172.50.2.10 | 172.50.2.100| HTTP   |
+------------------------------------------------------+
| Paket Detayları (Packet Details)                     |
|  > Frame 1: 74 bytes                                 |
|  > Ethernet II: Src: aa:bb:cc:dd:ee:ff              |
|  > Internet Protocol: Src: 172.50.2.100              |
|  > Transmission Control Protocol: Src Port: 12345    |
|  > Hypertext Transfer Protocol: GET / HTTP/1.1       |
+------------------------------------------------------+
| Paket İçeriği (Packet Bytes)                         |
|  0000: 00 0c 29 1a 2b 3c 00 50  ...                 |
|  Hex dump + ASCII gösterim                           |
+------------------------------------------------------+
```

### Panel Açıklamaları:

| Panel | Ne Gösterir | Nasıl Kullanılır |
|-------|-------------|-----------------|
| **Üst (Paket Listesi)** | Yakalanan tüm paketler | Tıkla = o paketi incele |
| **Orta (Paket Detayları)** | Seçili paketin katman katman analizi | Ok'lari aç = detay göster |
| **Alt (Paket Bytes)** | Seçili paketin ham hex verisi | Hex + ASCII gösterim |

## Adım 5: Renk Kodları

Wireshark protokolleri **renklere** göre ayırır:

| Renk | Protokol | Anlamı |
|------|----------|--------|
| Mavi | HTTP | Web trafiği |
| Koyu Yeşil | DNS | Domain sorguları |
| Mor | TCP | TCP kontrol paketleri (SYN, ACK, FIN) |
| Siyah | TCP (problem) | Yeniden iletim, sıralama sorunu |
| Açık Yeşil | TLS/SSL | Şifrelenmiş trafik |
| Kırmızı | ICMP | Ping gibi kontrol mesajları |
| Sarı | ARP | MAC-IP eşleştirme |

> Renklendirme kurallarını görmek için: **View > Coloring Rules**

## Adım 6: Temel İşlemler

### Paket Detaylarını İnceleme
1. Üst panelde bir pakete tıkla
2. Orta panelde `>` oklarına tıkla (her katmanı aç)
3. Her katmandaki alanları göreceksin:
   - **Frame**: Paket boyutu, yakalama zamanı
   - **Ethernet**: Kaynak/hedef MAC adresleri
   - **Internet Protocol (IP)**: Kaynak/hedef IP, TTL, Fragment
   - **TCP/UDP**: Port numaraları, Seq/Ack, Flags
   - **Uygulama (HTTP/DNS/...)**: Protokole özel veri

### Bir Konuşmayı Takip Etme (Follow Stream)
1. Bir HTTP paketine sağ tıkla
2. **Follow > TCP Stream**
3. Yeni pencerede tüm HTTP konuşmasını göreceksin (request + response)

### Filtre Yazma
En üstteki filtre çubuğuna yaz:
```
http                                    # Sadece HTTP paketleri
ip.addr == 172.50.2.10                 # Belirli IP ile ilgili her şey
tcp.port == 80                         # 80. porttaki trafik
http.request.method == "GET"           # Sadece GET istekleri
```

## Adım 7: İlk Capturing

Terminal'den su komutları çalıştır:

```bash
# 1. Ortamı başlat
cd /path/to/shark-tank   # shark-tank proje dizinine gidin
./scripts/start.sh

# 2. HTTP trafiği oluştur + capture et
./scripts/generate-traffic.sh http

# 3. Pcap dosyasını Wireshark ile aç
# macOS: open -a Wireshark shared/pcaps/module-01-basics.pcap
# Linux: wireshark shared/pcaps/module-01-basics.pcap &
# Windows: start wireshark shared/pcaps/module-01-basics.pcap
```

## Sınav Soruları (Çöz)

1. Yakalanan pcap'de kaç paket var?
2. İlk paketin kaynak IP'si nedir? Hedef IP'si?
3. Hangi protokoller görüyorsun? (Renklere bak)
4. Bir HTTP GET paketinin içindeki `User-Agent` header'i ne yazıyor?
5. `Follow TCP Stream` ile bir HTTP konuşmasını baştan sona oku. Request ve response'u ayır.

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **Paket sayısı değişkendir. `scripts/answer-key.sh` çalıştırın veya Wireshark durum çubuğundan (Packets: N) kontrol edin.**
2. **İlk TCP/IP paketi: Kaynak 172.50.2.100 (Client), Hedef 172.50.2.10 (Web Server). Not: Çok ilk paketler ARP/ICMPv6 (Docker altyapı) olabilir.**
3. **TCP, HTTP, ARP, DNS, ICMP: Protocol sütununa ve renklere bakın**
4. **curl/[sürüm]: container image'ındaki curl sürümüne bağlıdır**
5. **Request (GET /) ve Response (200 OK) olarak ayrılır. İstemcinin gönderdiği veri kırmızı, sunucunun yanıtı mavi renkte gösterilir.**

</details>

## Sınav İpuçları

- **Her zaman önce protokole göre filtrele**, sonra detaya in
- **Follow TCP Stream** sınavda en çok kullanılan özelliktir
- **Renk kodları** hızlı bir şekilde anomali tespit etmeni sağlar
- Paket detaylarında **+** işareti genişletilebilir alanları gösterir

## Wireshark Kısayolları ve Tercihler

### Klavye Kısayolları (Sınavda Zaman Kazandırır)

| Kısayol | İşlev |
|---------|-------|
| `Ctrl+E` | Capture başlat / durdur |
| `Ctrl+F` | Paket ara |
| `Ctrl+N` | Sonraki paket |
| `Ctrl+B` | Önceki paket |
| `Ctrl+.` | Bir sonraki işaretli pakete git |
| `Ctrl+M` | Paketi işaretle |
| `Tab` | Packet List → Packet Details geçişi |
| `Shift+Tab` | Packet Details → Packet List geçişi |
| `→` / `←` | Ağaç dallarını aç/kapat |
| `Ctrl+Shift+M` | Tüm işaretli paketleri filtrele |

### Edit > Preferences > Columns

Wireshark'ın sütunlarını özelleştirebilirsiniz:
1. **Edit > Preferences > Appearance > Columns**
2. Varsayılan: No., Time, Source, Destination, Protocol, Length, Info
3. **SINAV İPUCU:** "Response Time" sütunu ekleyin: `tcp.analysis.ack_rtt`: her paketin RTT'sini gösterir

### Edit > Configuration Profiles

Farklı analiz senaryoları için profil oluşturun:
1. **Edit > Configuration Profiles** (veya durum çubuğundan)
2. Yeni profil: "Security Analysis": sadece güvenlik filtreleri kayıtlı
3. Yeni profil: "Performance": TCP Stream Graph ve IO Graph ayarları
4. Profiller `.profile` dizininde saklanır

---

**Sonraki Modül:** [Wireshark Filtreleme](../module-02-filters/module-02-filters.md)