# Modül 20: Performans Analizi

**Neden?** Sistem yavaş, sebebi bulunamıyor. Yönetici "network kaynaklı" diyor ama kimse emin değil. Performans düşüşü çoğu zaman saldırının ilk belirtisidir: ani retransmission artışı (SYN flood), RTT dalgalanması (tunneling veya proxy), throughput düşüşü (DoS), Expert Info uyarıları (TCP Reset, Window violation). Performans metrikleri saldırıyı erken uyarı sistemi gibi yakalar. Bu modül: performans metriklerinden saldırıyı okumak.

**Görev:** Ağ performans sorunlarını TCP analizi ile tespit et.

**Öğrenim Hedefleri:**
- Yüksek RTT, retransmission ve Zero Window gibi performans sorunlarını tespit edebilmek
- Throughput = Window Size / RTT denklemini kavrayıp uygulayabilmek
- Window Scaling factor'ünün throughput'a etkisini anlamak
- Slow App Response ve Nagle gecikmesini ayırt edebilmek
- Expert Info ile performans anormalliklerini hızlıca bulabilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **TCP** | Transmission Control Protocol: internetin güvenilir ve sıralı veri iletimini sağlayan protokol. Veriyi göndermeden önce alıcıyla bağlantı kurar (3-way handshake), gönderdiği her paket için onay (ACK) bekler ve onay gelmeyen paketleri yeniden gönderir (retransmission). Bu mekanizmalar sayesinde veri kaybı olmadan ve gönderim sırasında bozulmadan teslim edilir. Web (HTTP), email (SMTP), dosya transferi (FTP) gibi kritik işlemlerin tamamı TCP üzerinden çalışır. Bağlantı kurma ve onay bekleme yükü nedeniyle UDP'den yavaştır, ama güvenilirlik gerektiğinde tek seçenektir. |
| **RTT** | Round Trip Time: bir paketin kaynaktan hedefe gidip geri dönmesi için geçen toplam süre. ICMP ping'inde, Echo Request'in gönderilmesi ile Echo Reply'nin alınması arasındaki süre RTT'dir. Wireshark bu değeri paket detaylarında `[Response Time: X.XXX ms]` olarak otomatik hesaplar. RTT, ağ gecikmesinin (latency) temel ölçüsüdür: düşük RTT hızlı bağlantıyı, yüksek RTT uzak veya tıkalı bir bağlantıyı gösterir. Sınavda `Edit > Time Display Format > Seconds Since Previous Packet` ile manuel RTT ölçümü de test edilir. |
| **throughput** | Bir ağ bağlantısında saniyede taşınan veri miktarı (byte/saniye veya bit/saniye). Throughput, bağlantının verimini ölçer: yüksek throughput hızlı veri transferini, düşük throughput darboğaz veya sorun olduğunu gösterir. Wireshark'ta Statistics → TCP Stream Graphs → Throughput grafiği, bir TCP bağlantısındaki veri aktarım hızını zaman içinde gösterir. Grafikteki ani düşüşler ağ tıkanıklığı, paket kaybı veya retransmission göstergesidir. Throughput ile bandwidth (bant genişliği) farklıdır: bandwidth ağ kapasitesidir, throughput ise bu kapasitenin ne kadarının fiilen kullanıldığıdır. |
| **retransmission** | TCP'de onay (ACK) gelmeyen bir paketin kaynak tarafından yeniden gönderilmesi. TCP güvenilir bir protokoldür: her gönderdiği paket için bir zamanlayıcı (timer) başlatır ve belirli süre içinde ACK gelmezse paketi tekrar gönderir. Wireshark retransmission paketlerini siyah renkle işaretler. Çok sayıda retransmission, ağ tıkanıklığı, kablosuz sinyal sorunu veya kasıtlı saldırı (ACK flood) gösterebilir. |
| **zero window** | TCP akış kontrolünde alıcının pencere boyutunu sıfır (0) olarak bildirmesi. TCP'de alıcı, kabul edebileceği veri miktarını "window size" alanında bildirir. Bu değer sıfır olduğunda alıcı şunu söyler: "Buffer'ım tamamen dolu, şu anda daha fazla veri alamam." Gönderici bu durumda veri göndermeyi durdurur ve periyodik olarak "Zero Window Probe" paketleri göndererek alıcının hazır olup olmadığını kontrol eder. Uzamış zero window durumları yavaş bir alıcı uygulaması, yetersiz buffer veya kaynak tüketimi saldırısını gösterebilir. |
| **Expert Information** | Wireshark'ın pcap içindeki anormallikleri ve sorunları otomatik olarak tespit edip listelediği panel. `View > Expert Information` (Ctrl+Alt+Shift+E) menüsünden açılır. Sorunları dört ciddiyet seviyesinde gruplar: Error (kırmızı), Warn (sarı), Note (mavi), Chat (yeşil). Bir analist pcap'i açtığında ilk bakması gereken yerlerden biridir; çünkü retransmission, duplicate ACK, zero window, HTTP 404 gibi sorunları paket tek tek aranmadan özet olarak gösterir. |

## Teori

TCP performansını etkileyen faktörler:

| Faktör | Etki | Tespit |
|--------|------|--------|
| **Yüksek RTT** | Uzun bekleme süreleri | RTT Graph > 100 ms |
| **Zero Window** | Alıcı tıkanıklığı | tcp.analysis.zero_window |
| **Retransmission** | Veri tekrarı | tcp.analysis.retransmission |
| **Dup ACK** | Sıra dışı paket | tcp.analysis.duplicate_ack |
| **Small Window** | Düşük throughput | Window Scaling Graph |
| **Window Scale** | Yanlış scale faktörü | TCP options (SYN) |
| **MSS** | Küçük segment boyutu | TCP options (SYN) |
| **Nagle** | Gecikmeli küçük paket | TCP_NODELAY eksik |

### Performans Denklemi:

```
Throughput = Window Size / RTT
  - Window Size = min(cwnd, rwnd)
  - RWND = Receive Window × Scale Factor
  - Örnek: 65535 byte window / 100 ms RTT = 5.2 Mbps
```

---

## Hazırlık

```bash
./scripts/generate-traffic.sh performance
```

---

## Alıştırma 1: Yüksek RTT Tespiti

Round Trip Time, bir paketin gidip gelme süresidir.

### Adımlar:

1. `shared/pcaps/module-20-performance.pcap`'i açın
2. Filtre: `tcp.stream == 0`
3. **Statistics → TCP Stream Graphs → Round Trip Time**
4. RTT değerlerini inceleyin:
   - Ortalama RTT kaç ms?
   - Maksimum RTT kaç ms?
   - RTT değişken mi (jitter) yoksa sabit mi?

### RTT Kaynaklı Sorunlar:

| Durum | RTT | Etki |
|-------|-----|------|
| Normal LAN | < 1 ms | ~ |
| Normal WAN | 10-50 ms | ~ |
| Yavaş WAN | 100-300 ms | Web sayfası yavaş açar |
| Uydu | > 500 ms | SSH kullanılamaz |
| Değişken | 1-200 ms | Video/voice bozulur |

> **SINAV İPUCU:** RTT yüksekse, throughput düşer: `Throughput = Window / RTT`. RTT iki katına çıkarsa throughput yarıya iner.

---

## Alıştırma 2: Zero Window Tespiti

Zero Window, alıcının uygulama katmanında veriyi işleyemediğini gösterir.

### Filtre:
```
tcp.analysis.zero_window
```

### Adımlar:

1. Filtre: `tcp.analysis.zero_window`
2. Zero Window varsa:
   - Hangi tarafta? (istemci mi sunucu mu?)
   - Ne sıklıkta tekrarlanıyor?
   - Zero Window Probe var mı? (`tcp.analysis.zero_window_probe`)
3. **Statistics → TCP Stream Graphs → Window Scaling**
   - Window size'ın sıfıra düştüğü anı görün

### Zero Window Nedenleri:

| Neden | Açıklama | Çözüm |
|-------|----------|-------|
| Slow App Server | Sunucu veriyi işleyemiyor | Uygulama optimizasyonu |
| Database Query | Uzun süren sorgu | Query optimizasyonu |
| Buffer Tuning | Küçük buffer | SO_RCVBUF artırma |
| Memory Pressure | Sistem belleği yetersiz | RAM yükseltme |

> **SINAV İPUÇLARI:**
>
> - Zero Window = alıcı taraflı sorun
> - Retransmission = ağ taraflı sorun (veya gönderici)
> - Zero Window Probe ile gönderici periyodik kontrol eder
> - Sık Zero Window = uygulama katmanında sorun

> **İstihbarat İşaretleri, Zero Window kötüye kullanımı:**
>
> - Zero window saldırısı: hedefin buffer'ını şişirme
> - Slow read saldırısı: HTTP slow read
> - Resource exhaustion tespiti

---

## Alıştırma 3: Slow Application Response

Sunucunun uygulama katmanında yavaş cevap vermesi.

### Tespit:

HTTP istek-response arasındaki süre:

```
İstek:     GET / HTTP/1.1
           [Zaman: T1]
           --- TCP ACK ---
           --- TCP ACK ---
           --- TCP ACK ---  <-- Bu arada sunucu düşünüyor
Response:  HTTP/1.1 200 OK
           [Zaman: T2]

İşlem Süresi = T2 - T1
```

### Adımlar:

1. `shared/pcaps/module-13-http.pcap`'i açın
2. Bir HTTP isteği seçin
3. **Follow → TCP Stream** ile akışı görün
4. İstek ile yanıt arasındaki zaman farkını hesaplayın:
   - HTTP request paketinin zamanı
   - HTTP response'un ilk paketinin zamanı
   - Aradaki fark = sunucu işlem süresi

### Performans Kategorileri:

| Süre | Değerlendirme |
|------|--------------|
| < 10 ms | Mükemmel |
| 10-100 ms | İyi |
| 100-500 ms | Kabul edilebilir |
| 500 ms - 2 sn | Yavaş |
| > 2 sn | Çok yavaş (kullanıcı terk eder) |

> **SINAV İPUCU:** İstek-response arası süre = Application Response Time. Bu süre uzunsa sorun sunucu uygulamasındadır, ağda değil.

---

## Alıştırma 4: Small Window ve Window Scale

Window size çok küçükse throughput düşer.

### Teori:

```
Gerçek Window = Window Size × 2^Window Scale

Örnek:
  Window Size = 65535
  Scale = 0 → gerçek window = 65535 bytes (64 KB)
  Scale = 7 → gerçek window = 65535 × 128 = 8 MB
```

### Adımlar:

1. SYN paketini bulun: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
2. TCP options'ı inceleyin:
   - **Window Scale**: kaç? (genelde 3, 7 veya 9)
   - **MSS**: kaç? (genelde 1460, 8960, 65535)
3. SYN-ACK paketini inceleyin:
   - Window Scale aynı mı? (her iki taraf da kabul etmeli)
   - MSS küçük olan kullanılır (path MTU)
4. Farklı akışlarda scale faktörlerini karşılaştırın

### Yanlış Yapılandırma Örnekleri:

| Sorun | Tespit | Etki |
|-------|--------|------|
| Scale 0 | SYN'de window scale yok | Max 64 KB window |
| Small MSS | MSS < 1000 | Header oranı yüksek |
| Asymmetric Scale | İstemci/sunucu scale farklı | İletişim sorunu |
| No Window Scale | Eski TCP stack | Düşük throughput |

> **SINAV İPUÇLARI:**
>
> - Window scale olmadan max window = 65535 byte
> - Scale 7 ile max window = 65535 × 128 = 8 MB
> - Scale SYN ve SYN-ACK'te belirlenir, bağlantı boyunca sabit
> - High-latency bağlantılarda window scale kritiktir

---

## Alıştırma 5: Retransmission Oranı Analizi

Retransmission oranı, ağ kalitesinin en önemli göstergesidir.

### Hesaplama:

```
Retransmission Rate = (Retransmission Paketleri / Toplam Paketler) × 100
```

### Adımlar:

1. Filtre: `tcp.analysis.retransmission` → retransmission sayısı
2. **Statistics → Capture File Properties** → toplam paket sayısı
3. Oranı hesaplayın:
   - < %1: Mükemmel
   - %1-3: Kabul edilebilir
   - %3-10: Sorunlu
   - > %10: Kritik (acil müdahale gerekli)
4. Hangi IP/port en çok retransmission üretiyor?
   - **Statistics → Endpoints** → TCP sekmesi
   - **Statistics → Conversations** → TCP sekmesi

### Retransmission Dağılımı:

```bash
# tshark ile en çok retransmission yapan IP'yi bul
tshark -r shared/pcaps/module-20-performance.pcap -Y "tcp.analysis.retransmission" \
  -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn
```

> **SINAV İPUCU:** Retransmission oranı > %3 ise ağ sorunu vardır. Hangi IP'nin en çok retransmission ürettiğini bulmak sorunun kaynağını belirler.

---

## Hızlı Referans - Performans Filtreleri

| Filtre | Anlamı |
|--------|--------|
| `tcp.analysis.retransmission` | Yeniden iletim |
| `tcp.analysis.zero_window` | Alıcı buffer dolu |
| `tcp.analysis.window_full` | Gönderici pencere limiti |
| `tcp.analysis.duplicate_ack` | Dup ACK |
| `tcp.analysis.ack_lost_segment` | Kayıp segment ACK |
| `tcp.analysis.bytes_in_flight` | Uçuştaki byte sayısı |
| `tcp.window_size < 1000` | Küçük pencere |

### Performans Analiz Sırası:

```
1. IO Graph → genel trafik deseni
2. Expert Information → Error/Warn tara
3. TCP Stream Graphs:
   a. RTT Graph → gecikme
   b. Throughput Graph → hız
   c. Window Scaling → flow control
4. Retransmission oranı hesapla
5. Application Response Time ölç
6. Window Scale ve MSS kontrol et
```

> **SINAV İPUCU:** Performans sorunu çözerken önce RTT'ye, sonra retransmission'a, sonra window'a bakılır. Application response time en son kontrol edilir (çünkü ağ sorunu değildir).

> **İstihbarat İşaretleri, Performans anomalileri:**
>
> - Normal trafiğe göre yüksek retransmission = ağ sabotajı
> - Belirli bir sunucuya sürekli zero window = hedef sistem zorlanıyor
> - Düşük throughput = bandwidth saturation veya throttling
> - Yüksek RTT + düşük window = TCP tuning gerekiyor

---

## Sınav Soruları (Çöz)

1. **Throughput = Window / RTT formülü ne anlama gelir? RTT iki katına çıkarsa throughput ne olur?**
2. **Zero Window hangi tarafı gösterir? Retransmission'dan farkı nedir?**
3. **Application response time nasıl ölçülür? Hangi durumda sorun ağdadır, hangi durumda uygulamadadır?**
4. **Window scale neden önemlidir? Scale olmadan max window boyutu nedir?**
5. **Retransmission oranı kaç olmalıdır? Hangi değer kritiktir?**
6. **High-latency bağlantılarda throughput'u artırmak için hangi TCP parametreleri ayarlanmalıdır?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **Throughput = Window Size / RTT. RTT iki katına çıkarsa throughput yarıya iner. Aynı throughput'u korumak için window size'ın iki katına çıkarılması gerekir.**

2. **Zero Window alıcı taraflı sorundur: uygulama veriyi işleyemiyor. Retransmission ağ taraflı veya gönderici taraflı sorundur: paket kayboldu veya ACK zamanında gelmedi.**

3. **İstek (HTTP Request) ile yanıt (HTTP Response) arasındaki zaman farkı ölçülür. RTT düşük ama response süresi yüksekse = uygulama sorunu. RTT yüksekse + response süresi de yüksekse = ağ sorunu.**

4. **Window scale, receive window'un 65535 byte'ın üzerine çıkmasını sağlar. Scale olmadan max window boyutu 65535 byte'tır (64 KB). Scale 7 ile 8 MB'a kadar çıkabilir.**

5. **< %1 mükemmel, %1-3 kabul edilebilir, %3-10 sorunlu, > %10 kritik. > %3 ise ağ sorunu araştırılmalıdır.**

6. **Window scale faktörü artırılmalı (yüksek scale), MSS doğru ayarlanmalı (path MTU), TCP_NODELAY (Nagle disable) kullanılmalı, buffer boyutları (SO_RCVBUF/SO_SNDBUF) artırılmalıdır.**

</details>

---

**Önceki Modül:** [TCP Grafikleri](../module-19-tcp-graph/module-19-tcp-graph.md)

**Sonraki Modül:** [WLAN Analizi](../module-21-wlan/module-21-wlan.md)
