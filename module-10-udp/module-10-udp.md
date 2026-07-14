# Modül 10: UDP Analizi

**Neden?** İnternet bağlantısı birden felç oldu. Trafik analizinde devasa miktarda UDP paketi görülüyor: DNS amplification DDoS. UDP'nin bağlantısız yapısı amplification saldırılarına açıktır: DNS amplification (küçük sorgu → büyük yanıt), NTP amplification, SNMP amplification, UDP flood. Saldırgan sahte kaynak IP ile küçük bir UDP paketi gönderir, hedef büyük yanıtla DDoS edilir. UDP tunneling ile veri sızdırılabilir. Bu modül: UDP tabanlı saldırıları tanımak.

**Görev:** UDP protokolünü analiz et. TCP'den farkını anla. Echo trafiğini incele.

**Öğrenim Hedefleri:**
- UDP header yapısını (8 byte: source/destination port, length, checksum) tanımak
- UDP'nin TCP'den farklarını (bağlantısız, güvenilmez, sırasız) kavramak
- Port unreachable (ICMP Type 3) mesajını tanımak
- UDP flood ve amplification saldırılarını (DNS, NTP, SNMP) tespit edebilmek
- UDP tunneling ile veri sızma yöntemlerini bilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **UDP** | User Datagram Protocol: bağlantı kurmadan doğrudan veri gönderen hızlı protokol. Handshake yoktur, onay (ACK) beklenmez, kaybolan paketler yeniden gönderilmez. Bu sayede TCP'den çok daha hızlı ve düşük gecikmeli çalışır, ancak güvenilirlik garantisi yoktur. DNS sorguları, video streaming, VoIP ve çevrimiçi oyunlar gibi hızın güvenilirlikten önemli olduğu uygulamalar UDP kullanır. Başlığı (header) sadece 8 byte'tır; TCP'nin minimum 20 byte'ına kıyasla çok daha hafiftir. |
| **port** | Bir cihaz üzerindeki uygulama girişi. 16 bitlik bir numaradır (0–65535) ve her ağ servisi belirli bir port numarasını kullanır: HTTP 80, HTTPS 443, DNS 53, FTP 21 gibi. Bir paket cihaza ulaştığında, port numarasına bakarak hangi uygulamaya teslim edileceği belirlenir. 0–1023 arası "well-known" (iyi bilinen) portlarıdır ve standart servislere ayrılmıştır. |
| **DNS** | Domain Name System: insan tarafından okunabilir alan adlarını (örn. `web.shark-tank.local`) IP adreslerine (örn. `172.50.2.10`) çeviren sistem. Cihazlar birbiriyle IP adresleriyle iletişim kurar, ama insanlar alan adlarını hatırlar; DNS bu çeviriyi yapar. Port 53 kullanır ve normalde UDP üzerinden çalışır. Güvenlik açısından DNS, veri sızdırmak (DNS tunneling) veya kullanıcıları sahte sitelere yönlendirmek (DNS poisoning) için istismar edilebilen bir protokoldür. |
| **ICMP** | Internet Control Message Protocol: ağ tanılama ve hata bildirimi için kullanılan protokol. Port kullanmaz; Layer 3'te (IP katmanı) doğrudan çalışır, bu yüzden "Layer 3.5" olarak da adlandırılır. En bilinen kullanımı ping komutudur: bir cihaza "orada mısın?" diye sorar (Echo Request), karşı taraf "evet, buradayım" diye yanıtlar (Echo Reply). traceroute aracı da ICMP kullanarak bir paketin geçtiği router'ları adım adım tespit eder. Güvenlik duvarları ICMP trafiğine genellikle izin verir; bu yüzden saldırganlar ICMP paketlerinin içine veri gizleyerek güvenlik duvarını aşabilir (ICMP tunneling). |
| **checksum** | Bir paketin içeriğinin bütünlüğünü doğrulamak için kullanılan matematiksel kontrol değeri. Her katmanın kendi checksum alanı vardır: IP header checksum, TCP checksum, UDP checksum. Gönderen taraf paketi iletirken içeriğe göre bir checksum hesaplar ve pakete ekler; alıcı taraf paketi aldığında aynı hesaplamayı yapıp sonucu karşılaştırır. Eşleşmezse paket bozulmuş demektir. Wireshark'ta checksum hatası (bad checksum), genellikle NIC offloading nedeniyle yakalama noktasında hesaplanmamış anlık checksum'ları gösterir ve her zaman gerçek bir hata anlamına gelmez. |
| **connectionless** | Bağlantısız: bir protokolün veri göndermeden önce alıcıyla bağlantı kurmaması (handshake yapmaması) özelliği. UDP connectionless bir protokoldür: gönderen, alıcının hazır olup olmadığını kontrol etmeden, onay beklemeden doğrudan veriyi gönderir. Bu, hız ve basitlik avantajı sağlar ama güvenilirlik dezavantajı yaratır: paket kaybı olursa gönderen haberdar olmaz. TCP ise connection-oriented'tır (bağlantı odaklı): önce 3-way handshake ile bağlantı kurar, sonra veri gönderir, her paket için onay bekler. Connectionless yapı, UDP'yi amplification saldırılarına da açık hale getirir: saldırgan sahte kaynak IP'si ile UDP paketi gönderebilir, çünkü doğrulama adımı yoktur. |
| **Destination Unreachable** | ICMP Type 3 mesajı: bir paketin hedefe ulaşamadığını bildiren hata mesajı. Code alanı altında farklı nedenler belirtilir: Network Unreachable (Code 0, ağa giden yol yok), Host Unreachable (Code 1, cihaz kapalı veya yanıt vermiyor), Port Unreachable (Code 3, hedef portta servis çalışmıyor). Güvenlik duvarları genellikle paketleri sessizce düşürür, bu yüzden Destination Unreachable görmek ya gerçek bir ağ sorunu ya da ICMP döndüren bir güvenlik duvarı anlamına gelir. |
| **amplification** | UDP'nin bağlantısız yapısından kaynaklanan bir saldırı tekniği. Saldırgan, sahte (spoofed) kaynak IP adresiyle küçük bir UDP sorgusu gönderir (örneğin DNS'e 60 byte'lık bir istek). Sunucu yanıtı sahte kaynak IP'sine (kurban) gönderir, ancak yanıt çok daha büyüktür (örneğin 4000 byte). Böylece saldırgan küçük bir çabayla kurbanın üzerine büyük miktarda veri yönlendirir: bu "amplification" (yükseltme) olarak adlandırılır. DNS, NTP ve SNMP en yaygın amplification vektörleridir. UDP'de handshake olmadığı için sunucu, sorgunun gerçekten sahte IP'den gelip gelmediğini doğrulayamaz. |

## Teori

UDP (User Datagram Protocol), bağlantısız (connectionless) ve güvenilmez (unreliable) bir transport katmanı protokolüdür.

- **Bağlantısız:** Handshake yok. Veri doğrudan gönderilir.
- **Güvenilmez:** ACK yok, retransmission yok. Paket kaybolursa gönderen bunu bilmez.
- **Sırasız:** Paketler varış sırasına göre gelmeyebilir. Sıralama uygulama katmanına bırakılır.
- **Hızlı:** Kontrol mekanizması olmadığı için TCP'den çok daha hızlı ve düşük gecikmeli.
- **Başlık (header):** Sadece 8 byte. TCP'nin minimum 20 byte'lık başlığına kıyasla çok hafif.

### UDP Header Yapısı (8 byte):

```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source Port   |  Destination Port |   4 byte
+--------+--------+--------+--------+
|      Length       |     Checksum     |   4 byte
+--------+--------+--------+--------+
|              Data (payload)               |
+-------------------------------------------+
```

| Alan | Boyut | Açıklama |
|------|-------|----------|
| **Source Port** | 2 byte | Gönderen port (0-65535) |
| **Destination Port** | 2 byte | Hedef port (0-65535) |
| **Length** | 2 byte | UDP başlık + veri toplam boyutu (minimum 8) |
| **Checksum** | 2 byte | Hata kontrolü (isteğe bağlı, IPv4'te) |

### TCP vs UDP Karşılaştırma:

| Özellik | TCP | UDP |
|---------|-----|-----|
| Bağlantı | Connection-oriented (handshake) | Connectionless |
| Güvenilirlik | Güvenilir (ACK, retransmission) | Güvenilmez (onay mekanizması yok) |
| Sıralama | Paketler sıralı teslim edilir | Sıralama garantisi yok |
| Hız | Yavaş (kontrol overhead'ı var) | Hızlı (minimum overhead) |
| Başlık boyutu | Minimum 20 byte | 8 byte (sabit) |
| Akış kontrolü | Var (window sizing) | Yok |
| Tıkanıklık kontrolü | Var | Yok |
| Kullanım | Web, e-posta, dosya transferi | DNS, DHCP, NTP, VoIP, oyun, streaming |

### Yaygın UDP Protokolleri:

| Protokol | Port | Açıklama |
|----------|------|----------|
| **DNS** | 53 | Domain adı çözümleme |
| **DHCP** | 67/68 | IP adresi atama |
| **NTP** | 123 | Zaman senkronizasyonu |
| **SNMP** | 161/162 | Ağ yönetimi |
| **TFTP** | 69 | Basit dosya transferi |
| **RTP** | 5004+ | VoIP / video streaming |
| **Syslog** | 514 | Log mesajları |

> **İstihbarat İşaretleri, UDP, saldırıların gizli kanalı olabilir:**
>
> - Çok sayıda UDP paketi farklı portlara = UDP port scan
> - UDP flood = DDoS saldırısı (amplification)
> - DNS over UDP ile exfiltration mümkün
> - UDP kaynak IP spoof edilebilir (handshake yok, doğrulama yok)
> - UDP tabanlı amplification saldırılarında küçük bir istek büyük bir response üretir (DNS, NTP, SNMP)

## Hazırlık

```bash
./scripts/generate-traffic.sh udp
# macOS: open -a Wireshark shared/pcaps/module-10-udp.pcap
# Linux: wireshark shared/pcaps/module-10-udp.pcap &
# Windows: start wireshark shared/pcaps/module-10-udp.pcap
```

## Alıştırma 1: UDP Paket Yapısı

### Filtre:
```
udp
```

### Adımlar:
1. Herhangi bir UDP paketine tıkla
2. Orta panelde **User Datagram Protocol** katmanını genişlet:

```
 v User Datagram Protocol
     Source Port: 45678                <-- Gönderen port (ephemeral)
     Destination Port: 9090            <-- Hedef port (UDP Echo server)
     Length: 24                        <-- UDP başlık + veri = 8 + 16 byte
     Checksum: 0xXXXX                  <-- Hata kontrolü
     [Stream index: 0]
```

3. Dikkat et: **Length alanı başlık + veri toplamıdır.** Minimum 8 byte (sadece başlık, veri yok).
4. UDP başlığı sadece 8 byte. TCP başlığı en az 20 byte ile karşılaştır.

> **SINAV İPUCU:** UDP header her zaman 8 byte'dır, sabit. TCP header ise 20-60 byte arasında değişir (options alanı nedeniyle).

## Alıştırma 2: TCP vs UDP Karşılaştırma

### Filtre:
```
udp || tcp
```

### Adımlar:
1. Hem TCP hem UDP paketlerini aynı ekranda gör
2. TCP paketlerine bak: Flags alanı var (SYN, ACK, FIN), Sequence number var, Acknowledgment number var
3. UDP paketlerine bak: Flags yok, Sequence yok, Acknowledgment yok. Sadece port, uzunluk, checksum
4. Protocol sütununda TCP ve UDP'yi ayır:

```
tcp                     # Sadece TCP paketleri
udp                     # Sadece UDP paketleri
```

5. Kaç TCP, kaç UDP paketi var? Say:

```
Statistics > Summary
```

> **SINAV İPUCU:** TCP'de bağlantı kurma (SYN), veri transferi ve bağlantı kapatma (FIN) aşamaları vardır. UDP'de hiçbiri yok. Paket doğrudan gönderilir, bağlantı kavramı yoktur.

## Alıştırma 3: UDP Echo Analizi

### Filtre:
```
ip.addr == 172.50.2.17 && udp.port == 9090
```

UDP Echo sunucusu 172.50.2.17:9090'da çalışıyor. Gönderilen her mesajı aynen geri gönderir.

### Adımlar:
1. İstemciden sunucuya giden bir UDP paketi bul (Destination Port: 9090)
2. Sunucudan istemciye dönen paketi bul (Source Port: 9090)
3. Gönderilen veri ile dönen veriyi karşılaştır: aynı mı?
4. İstek-yanıt çiftlerini say

### Örnek Akış:
```
CLIENT (sen)                    ECHO SERVER (172.50.2.17:9090)
  |--- UDP "Merhaba" ---------->|    İstek (dst port: 9090)
  |<-- UDP "Merhaba" -----------|    Yanıt (src port: 9090)
  |--- UDP "Test mesajı" ------>|
  |<-- UDP "Test mesajı" -------|
```

### Önemli Soru:
TCP Echo'da olduğu gibi garantili yanıt var mı? Hayır. UDP'den sonra bir yanıt gelmesi beklenir ama garanti değildir. Paket yolda kaybolursa ne olur? Hiçbir şey. Gönderen haberdar olmaz.

> **SINAV İPUCU:** UDP Echo istek-yanıt çiftleri birbirine benzer ama TCP'deki gibi SEQ/ACK numaralarıyla eşleşmez. IP adresi ve port numarasıyla eşleştirilir.

## Alıştırma 4: UDP Port Unreachable

### Filtre:
```
icmp.type == 3
```

Kapalı bir UDP portuna paket gönderildiğinde TCP'deki gibi RST gelmez. Bunun yerine **ICMP Destination Unreachable (Port Unreachable)** mesajı gelir.

### Adımlar:
1. ICMP Type 3 paketini bul
2. **Internet Control Message Protocol** katmanını genişlet
3. Code alanını kontrol et: Code 3 = Port Unreachable

```
 Type: 3 (Destination unreachable)
 Code: 3 (Port unreachable)
```

4. ICMP paketinin içinde, neden gönderildiğini gösteren orijinal UDP paketi vardır. Genişlet:

```
 v Internet Control Message Protocol
     Type: 3 (Destination unreachable)
     Code: 3 (Port unreachable)
     ...
     v Datagram payload (original packet)
         Source Port: XXXXX
         Destination Port: YYYY   <-- Kapalı port
```

> **SINAV İPUCU:** TCP'de kapalı port = RST. UDP'de kapalı port = ICMP Port Unreachable (Type 3, Code 3). Ama dikkat: bazı sistemler kapalı UDP portlarına sessiz kalır (hiçbir yanıt göndermez). Bu durumda paketin kaybolduğu anlaşılamaz.

## Alıştırma 5: DNS over UDP

DNS sorguları çoğunlukla UDP port 53 üzerinden yapılır.

### Filtre:
```
dns && udp
```

### Adımlar:
1. Bir DNS query paketi bul (Standard query)
2. **User Datagram Protocol** katmanına bak: Destination Port: 53
3. Eşleşen DNS response'u bul: Aynı Transaction ID'ye sahip
4. Query ve response arasında UDP kullanıldığını doğrula

### DNS Query/Response Eşleştirme:
- Her DNS sorgusunun bir **Transaction ID**'si vardır
- Query ve Response aynı Transaction ID'ye sahiptir
- UDP olduğu için bu eşleştirme application katmanında (DNS) yapılır, transport katmanında değil

> **SINAV İPUCU:** DNS çoğunlukla UDP kullanır (yanıt 512 byte'tan kısaysa). Zone transfer ve uzun yanıtlar TCP kullanır. Sınavda "DNS hangi transport protokolü kullanır?" sorusuna **UDP (çoğunlukla)** cevap verin.

## Alıştırma 6: UDP Checksum Doğrulama

### Adımlar:
1. **Edit > Preferences > Protocols > UDP**
2. **"Validate the UDP checksum if possible"** seçeneğini aktif et
3. UDP paketlerini incele: Wireshark checksum'ı doğrular
4. Eğer checksum hatalıysa Wireshark kırmızı ile gösterir:

```
 [Bad UDP checksum: 0xXXXX (should be: 0xYYYY)]
```

5. Herhangi bir checksum hatası var mı? Kontrol et

### Not:
IPv4'te UDP checksum isteğe bağlıdır (0x0000 = checksum devre dışı). IPv6'da ise zorunludur.

> **SINAV İPUCU:** UDP checksum IPv4'te isteğe bağlıdır. Checksum 0x0000 ise "checksum hesaplanmadı" anlamına gelir. IPv6'da checksum zorunludur.

## Alıştırma 7: Follow UDP Stream

### Adımlar:
1. Herhangi bir UDP paketine sağ tıkla
2. **Follow > UDP Stream**
3. Ayrı bir pencerede UDP akışı gösterilir

### TCP Stream ile Farkı:
- TCP'de stream numarası bağlantıya özeldir (tcp.stream == 0, 1, 2...)
- UDP'de stream numarası IP ve port çiftine göre atanır
- UDP connectionless olduğu için "bağlantı" kavramı yoktur
- Aynı IP/port çifti arasındaki tüm paketler bir stream'de gösterilir

> **SINAV İPUCU:** Follow UDP Stream, TCP'deki gibi çalışır ama bağlantı tabanlı değildir. Aynı endpoint çifti arasındaki tüm paketleri gösterir.

## Filtre Referansı

| Filtre | Açıklama |
|--------|----------|
| `udp` | Tüm UDP paketleri |
| `udp.port == 9090` | Port 9090 (kaynak veya hedef) |
| `udp.srcport == 9090` | Kaynak port 9090 |
| `udp.dstport == 9090` | Hedef port 9090 |
| `udp.length == 24` | Belirli uzunlukta UDP paketleri |
| `udp.checksum == 0x0000` | Checksum hesaplanmamış paketler |
| `udp.contains "Merhaba"` | UDP payload'ında "Merhaba" |
| `ip.addr == 172.50.2.17 && udp` | Belirli IP ile UDP |
| `dns && udp` | DNS over UDP |
| `icmp.type == 3 && icmp.code == 3` | ICMP Port Unreachable |
| `udp.port == 53` | DNS (UDP port 53) |
| `udp.port == 67 \|\| udp.port == 68` | DHCP |
| `udp.port == 123` | NTP |
| `udp.port == 161` | SNMP |
| `udp.port == 514` | Syslog |
| `!(tcp) && !(arp) && !(icmp)` | TCP/ARP/ICMP olmayan (çoğunlukla UDP) |

> **SINAV İPUCU:** UDP sınavda TCP ile karşılaştırma olarak sorulur. "Hangi protokol connectionless?" cevap: UDP. "DNS hangi transport kullanır?" cevap: UDP (çoğunlukla, TCP de destekler). "UDP header kaç byte?" cevap: 8 byte. "UDP'de retransmission var mı?" cevap: Yok.

> **İstihbarat İşaretleri, UDP, saldırıların gizli kanalı olabilir:**
>
> - Çok sayıda UDP paketi farklı portlara = UDP port scan (nmap -sU)
> - UDP flood = DDoS saldırısı (amplification: DNS, NTP, SNMP ile küçük istek, büyük yanıt)
> - DNS over UDP ile exfiltration mümkün
> - UDP kaynak IP spoof edilebilir (handshake yok, doğrulama mekanizması yok)
> - Normalde sessiz olan bir host'tan aniden çok sayıda UDP paketi = compromised olabilir

## Sınav Soruları (Çöz)

1. **UDP header kaç byte'dır? Hangi alanları içerir?**
2. **UDP'de three-way handshake var mıdır? Açıklayın.**
3. **UDP ile TCP'nin en büyük farkı nedir?**
4. **DNS hangi transport katmanı protokolü kullanır?**
5. **Kapalı bir UDP portuna paket gönderilirse ne olur?**
6. **UDP Echo sunucusuna (172.50.2.17:9090) gönderilen bir paketin garantili yanıt aldığını söyleyebilir miyiz?**
7. **UDP checksum IPv4'te zorunlu mudur?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **8 byte. Source Port (2), Destination Port (2), Length (2), Checksum (2).**
2. **Yok. UDP connectionless bir protokoldür. Bağlantı kurulmadan veri doğrudan gönderilir.**
3. **Güvenilirlik (reliability). TCP güvenilirdir (ACK, retransmission, sıralama). UDP güvenilmezdir (onay mekanizması yok, kayıp paket tespiti yok).**
4. **UDP (çoğunlukla). Yanıt 512 byte'tan uzunsa veya zone transfer ise TCP kullanılır.**
5. **ICMP Destination Unreachable (Port Unreachable, Type 3 Code 3) mesajı dönebilir. Bazı sistemler sessiz kalır (hiçbir yanıt göndermez).**
6. **Hayır. UDP güvenilmezdir. Echo sunucusu yanıtı gönderir ama bu yanıtın istemciye ulaşacağı garanti değildir. Ayrıca istemcinin isteğinin sunucuya ulaşacağı da garanti değildir.**
7. **Hayır, IPv4'te isteğe bağlıdır. Checksum alanı 0x0000 ise hesaplanmamış demektir. IPv6'da zorunludur.**

</details>

---

**Önceki Modül:** [TCP Dizi Analizi](../module-09-tcp-sequence/module-09-tcp-sequence.md)

**Sonraki Modül:** [TCP Akış Analizi](../module-11-advanced-tcp/module-11-advanced-tcp.md)
