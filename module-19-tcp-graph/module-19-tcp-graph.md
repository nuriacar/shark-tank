# Modül 19: TCP Grafikleri

**Neden?** C2 sunucusuyla iletişim düzenli aralıklarla gerçekleşiyor. Paket listesine bakınca görmek zor, ama grafiğe dökünce desen belli oluyor. Saldırı grafiklerde anomali olarak görünür: IO Graph'da throughput spike (DDoS veya veri sızdırma), Flow Graph'da ani bağlantı artışı (port scan veya botnet aktivasyonu), Stream Graph'da düzenli aralıklarla tekrar eden trafik (C2 beaconing). Sayısal veri gözle görülmeyen saldırıyı ortaya çıkarır. Bu modül: grafiklerle saldırı desenlerini okumak.

**Görev:** Wireshark grafik araçlarıyla TCP davranışını görselleştir.

**Öğrenim Hedefleri:**
- IO Graph ile genel trafik yoğunluğunu ve throughput spike'ları görebilmek
- TCP Stream Graph (Time-Sequence, Throughput, RTT) ile tek bir akışı analiz edebilmek
- Grafiklerdeki anormallikleri (DDoS, C2 beaconing, port scan) tespit edebilmek
- Flow Graph ile bağlantı akışını görsel olarak takip edebilmek
- Grafik verilerini CSV/PDF olarak dışa aktarabilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **IO Graph** | Wireshark'ın tüm trafiğin zaman içindeki dağılımını gösteren genel amaçlı grafik aracı. `Statistics → IO Graph` menüsünden açılır. X ekseni zamanı, Y ekseni paket/saniye veya byte/saniyeyi gösterir. Belirli zaman aralıklarında (interval) trafik yoğunluğunu görselleştirir: ani spike'lar DDoS veya veri sızdırma, düz ve düşük seviye normal trafiği gösterir. Display filter ile farklı protokolleri veya IP'leri ayrı renklerde çizdirebilirsiniz. Sınavda "hangi grafik toplam trafik yoğunluğunu gösterir?" sorusunun cevabı IO Graph'tir. |
| **Flow Graph** | Wireshark'ın paketlerin zaman içindeki akışını görsel olarak gösteren diyagram aracı. `Statistics → Flow Graph` menüsünden açılır. Her satır bir cihazı (IP/MAC), her ok bir paketi temsil eder; iletişimin başlangıcından sonuna kadar kimin ne zaman ne gönderdiği tek bir görüntüde özetlenir. Özellikle TCP 3-way handshake ve bağlantı kapatma süreçlerini, port scan desenlerini ve çoklu cihaz etkileşimini görselleştirmek için kullanılır. Sınavda bir saldırının zaman çizelgesini oluşturmak için Flow Graph kullanımı test edilir. |
| **TCP Stream Graph** | Wireshark'ın tek bir TCP bağlantısını (stream) derinlemesine analiz eden dört farklı grafikten oluşan araç seti. `Statistics → TCP Stream Graphs` menüsü altında dört grafik bulunur: Time-Sequence (tcptrace): sequence number'ın zaman içindeki ilerleyişini ve retransmission'ları gösterir; Throughput: saniyedeki veri miktarını gösterir; Round Trip Time: her paketin gidiş-dönüş süresini gösterir; Window Scaling: alıcının window boyutunun zaman içindeki değişimini gösterir. IO Graph tüm trafiği gösterirken, TCP Stream Graph tek bir bağlantıya odaklanır. |
| **TCP** | Transmission Control Protocol: internetin güvenilir ve sıralı veri iletimini sağlayan protokol. Veriyi göndermeden önce alıcıyla bağlantı kurar (3-way handshake), gönderdiği her paket için onay (ACK) bekler ve onay gelmeyen paketleri yeniden gönderir (retransmission). Bu mekanizmalar sayesinde veri kaybı olmadan ve gönderim sırasında bozulmadan teslim edilir. Web (HTTP), email (SMTP), dosya transferi (FTP) gibi kritik işlemlerin tamamı TCP üzerinden çalışır. Bağlantı kurma ve onay bekleme yükü nedeniyle UDP'den yavaştır, ama güvenilirlik gerektiğinde tek seçenektir. |
| **throughput** | Bir ağ bağlantısında saniyede taşınan veri miktarı (byte/saniye veya bit/saniye). Throughput, bağlantının verimini ölçer: yüksek throughput hızlı veri transferini, düşük throughput darboğaz veya sorun olduğunu gösterir. Wireshark'ta Statistics → TCP Stream Graphs → Throughput grafiği, bir TCP bağlantısındaki veri aktarım hızını zaman içinde gösterir. Grafikteki ani düşüşler ağ tıkanıklığı, paket kaybı veya retransmission göstergesidir. Throughput ile bandwidth (bant genişliği) farklıdır: bandwidth ağ kapasitesidir, throughput ise bu kapasitenin ne kadarının fiilen kullanıldığıdır. |
| **RTT** | Round Trip Time: bir paketin kaynaktan hedefe gidip geri dönmesi için geçen toplam süre. ICMP ping'inde, Echo Request'in gönderilmesi ile Echo Reply'nin alınması arasındaki süre RTT'dir. Wireshark bu değeri paket detaylarında `[Response Time: X.XXX ms]` olarak otomatik hesaplar. RTT, ağ gecikmesinin (latency) temel ölçüsüdür: düşük RTT hızlı bağlantıyı, yüksek RTT uzak veya tıkalı bir bağlantıyı gösterir. Sınavda `Edit > Time Display Format > Seconds Since Previous Packet` ile manuel RTT ölçümü de test edilir. |

## Teori

Wireshark'ın grafik araçları, sayısal veriyi görsel hale getirerek trafik desenlerini, anormallikleri ve performans sorunlarını anlamayı kolaylaştırır.

### IO Graph vs TCP Stream Graph:

| Özellik | IO Graph | TCP Stream Graph |
|---------|----------|-----------------|
| **Kapsam** | Tüm paketler | Tek bir TCP akışı |
| **X ekseni** | Zaman (sabit aralık) | Zaman veya paket no |
| **Y ekseni** | Paket/s, Byte/s, ... | Seq no, byte/s, RTT, window |
| **Filtre** | Display filter | TCP stream seçimi |
| **Kullanım** | Genel trafik analizi | Derin TCP analizi |

---

## Hazırlık

```bash
./scripts/generate-traffic.sh tcp-graph
```

---

## Alıştırma 1: IO Graph Temel Kullanımı

IO Graph, tüm trafiğin zaman içindeki dağılımını gösterir.

### Adımlar:

1. `shared/pcaps/module-19-tcp-graph.pcap`'i Wireshark'ta açın
2. **Statistics → IO Graph**
3. Varsayılan grafik: tüm paketler (paket/saniye)
4. Grafik ayarları:
   - **X Axis**: Time (sec): zaman aralığı
   - **Interval**: 1 sec: her sütun 1 saniye
   - **Y Axis**: Packets/Tick: paket sayısı
   - **Style**: Line: çizgi grafik
5. Grafikteki **tepe noktaları** ne anlama geliyor?
   - Ani yükseliş = trafik patlaması (burst)
   - Düzlük = sessizlik
   - Periyodik tepe = tarama (scan) veya polling

### Birden Fazla Filtre Ekleme:

1. **IO Graph** penceresinde **Add** butonu ile yeni grafik çizgisi ekleyin:
   - **Line 2**: `tcp.port == 80` → HTTP trafiği
   - **Line 3**: `tcp.port == 443` → HTTPS trafiği  
   - **Line 4**: `dns` → DNS trafiği
2. Her satır için farklı renk seçin
3. Hangi protokol en yoğun? Hangi zaman aralığında?

> **SINAV İPUÇLARI:**
>
> - IO Graph = **zaman bazlı** trafik dağılımı
> - Interval küçüldükçe detay artar, büyüdükçe genel desen görünür
> - Her grafik satırına ayrı display filter uygulanabilir
> - **Smooth** seçeneği grafiği yumuşatır, tepe noktaları azalır

> **İstihbarat İşaretleri, IO Graph anormallik tespiti:**
>
> - Normalden yüksek trafik = veri sızıntısı veya DDoS
> - Periyodik tepeler = beaconing (C2 iletişimi)
> - Belirli protokolde ani artış = o protokole yönelik saldırı

---

## Alıştırma 2: IO Graph İleri Düzey

### Y Ekseni Türleri:

| Y Axis | Anlamı | Kullanım |
|--------|--------|----------|
| **Packets/Tick** | Paket sayısı | Genel yoğunluk |
| **Bytes/Tick** | Byte hacmi | Bant genişliği kullanımı |
| **Bits/Tick** | Bit hızı | Hat hızı karşılaştırması |
| **Advanced...** | SUM/AVG/MAX/MIN | İstatistiksel |

### Adımlar:

1. **IO Graph** açın, yeni bir Line ekleyin:
   - Filter: `tcp.analysis.retransmission`
   - Style: Bar (sütun)
   - Color: Kırmızı
2. İkinci Line ekleyin:
   - Filter: `tcp.analysis.zero_window`
   - Style: Bar
   - Color: Turuncu
3. Y Axis tipini **Bytes/Tick** yapın → bant genişliği kullanımını görün
4. Interval'i değiştirin:
   - 0.1 sn: çok detaylı, gürültülü
   - 10 sn: genel desen, detay kaybolur
   - **1 sn**: ideal denge

### Zoom ve Navigasyon:

- **Fare tekeri**: Zoom in/out
- **Sürükle**: Zaman aralığı seç
- **Sağ tık → Zoom In/Out**: Detaylı inceleme
- **Save As**: Grafik PNG olarak kaydedilebilir

> **SINAV İPUÇLARI:**
>
> - **Y Axis değişimi** grafiğin yorumunu tamamen değiştirir
> - **Bytes/Tick** bant genişliği analizi için kullanılır
> - Retransmission grafiği üst üste binmişse = ağ sorunu
> - Bar stili tepe noktalarını vurgulamak için idealdir

---

## Alıştırma 3: Time-Sequence Graph (tcptrace)

TCP stream'de sequence number'ların zaman içindeki ilerleyişini gösterir.

### Adımlar:

1. `shared/pcaps/module-19-tcp-graph.pcap`'i açın
2. İlk TCP akışını seçin: Filtre `tcp.stream == 0`
3. **Statistics → TCP Stream Graphs → Time-Sequence (tcptrace)**
4. Grafiği yorumlayın:

```
Seq No
  ^
  |     /    /    /    /
  |    /    /    /    /          <- Düz çizgi = normal akış
  |   /    /    /    /
  |  /    /    ___/
  | /    /    /                  <- Geri sıçrama = RETRANSMISSION!
  |/ ___/    /
  +--------------------------------> Zaman
```

5. **Retransmission** varsa:
   - Seq no geri sıçrar (düşüş)
   - Aynı seq no tekrar gönderilir
6. **Slow Start** fazı:
   - Başlangıçta yavaş artış
   - Sonra hızlanma (exponential growth)

> **SINAV İPUÇLARI:**
>
> - Düz çizgi = normal TCP akışı
> - **Geri sıçrama = Retransmission**
> - Slow Start: eğri artan çizgi (exponential)
> - Congestion Avoidance: doğrusal artan çizgi

---

## Alıştırma 4: Throughput Graph

TCP stream'in bant genişliği kullanımını zaman içinde gösterir.

### Adımlar:

1. `shared/pcaps/module-19-tcp-graph.pcap`: `tcp.stream == 0`
2. **Statistics → TCP Stream Graphs → Throughput**
3. Grafiği yorumlayın:
   - Y ekseni: Byte/saniye
   - Tepe noktaları: maksimum throughput
   - Düşüşler: ağ sorunu veya retransmission

### Throughput Desenleri:

| Desen | Anlamı |
|-------|--------|
| **Kararlı throughput** | Sağlıklı bağlantı |
| **Ani düşüş** | Paket kaybı, retransmission |
| **Düzensiz dalgalanma** | Ağ tıkanıklığı |
| **Sıfıra düşüş** | Bağlantı kopması veya zero window |

> **SINAV İPUÇLARI:**
>
> - Throughput Graph = **gerçek transfer hızı**
> - Ani düşüşler genellikle retransmission kaynaklıdır
> - Slow Start'ta throughput exponential artar
> - Loss sonrası throughput yarıya düşer

---

## Alıştırma 5: Round Trip Time (RTT) Graph

Her paketin gidiş-geliş süresini (RTT) gösterir.

### Adımlar:

1. `shared/pcaps/module-19-tcp-graph.pcap`: `tcp.stream == 0`
2. **Statistics → TCP Stream Graphs → Round Trip Time**
3. Grafiği yorumlayın:
   - Y ekseni: RTT (milisaniye)
   - Düşük RTT = hızlı ağ
   - Yüksek RTT = gecikmeli ağ
   - Değişken RTT = dengesiz ağ

### RTT Değerleri:

| RTT | Ağ Durumu |
|-----|-----------|
| < 1 ms | Aynı anahtar/switch (çok hızlı) |
| 1-10 ms | Aynı veri merkezi |
| 10-50 ms | Metropol ağı |
| 50-150 ms | Kıtalararası |
| > 150 ms | Uydu veya çok yavaş bağlantı |

> **SINAV İPUÇLARI:**
>
> - RTT artışı = ağ gecikmesi
> - Değişken RTT = ağ dengesizliği (jitter)
> - RTT, retransmission timeout (RTO) hesaplamasında kullanılır (RTO ≈ 2-4× RTT)

---

## Alıştırma 6: Window Scaling Graph

Receive window boyutunun zaman içindeki değişimi.

### Adımlar:

1. `shared/pcaps/module-19-tcp-graph.pcap`: `tcp.stream == 0`
2. **Statistics → TCP Stream Graphs → Window Scaling**
3. Grafiği yorumlayın:
   - Y ekseni: Window size (byte)
   - Yüksek window = alıcı hazır
   - **Sıfır window = alıcı buffer dolu (Zero Window)**

### Window Desenleri:

| Desen | Anlamı |
|-------|--------|
| **Sabit window** | Sağlıklı akış |
| **Azalan window** | Alıcı yavaşlıyor |
| **Sıfır window** | Alıcı tıkandı (flow control) |
| **Ani artış** | Window scale uygulandı |

> **SINAV İPUÇLARI:**
>
> - Window Scaling Graph = alıcının durumu
> - Zero Window = flow control aktif
> - Window scale factor SYN'de belirlenir, bağlantı boyunca sabittir
> - Gerçek window = window size × 2^scale_factor

---

## Hızlı Referans - Grafik Araçları

| Menü | Kısayol | Amaç |
|------|---------|------|
| Statistics → IO Graph | - | Genel trafik dağılımı |
| Statistics → TCP Stream Graphs → Time-Sequence | - | Seq no / retransmission |
| Statistics → TCP Stream Graphs → Throughput | - | Bant genişliği |
| Statistics → TCP Stream Graphs → Round Trip Time | - | Gecikme analizi |
| Statistics → TCP Stream Graphs → Window Scaling | - | Flow control |

### IO Graph Kullanım İpuçları:

| İşlem | Açıklama |
|-------|----------|
| Add | Yeni filtre satırı ekle |
| Interval | Zaman aralığı (1 sn default) |
| Y Axis | Paket, byte, bit veya özel |
| Style | Line, Bar, Impulse, FBar, Dot |
| Smooth | Grafik yumuşatma |
| Copy | Grafiği PNG/clipboard'a kopyala |

> **SINAV İPUCU:** IO Graph ve TCP Stream Graph arasındaki fark sınavda sorulabilir. IO Graph tüm trafik içindir, TCP Stream Graph tek bir akış içindir.

> **İstihbarat İşaretleri, Grafiklerle anomali tespiti:**
>
> - IO Graph: Ani trafik artışı = DDoS veya veri sızıntısı
> - Time-Sequence: Geri sıçrama = retransmission
> - Throughput: Ani düşüş = ağ sorunu
> - RTT: Yükselme = gecikme
> - Window Scaling: Sıfır = alıcı tıkanıklığı

---

## Sınav Soruları (Çöz)

1. **IO Graph ile TCP Stream Graph arasındaki fark nedir?**
2. **Time-Sequence Graph'da seq numarasının geri sıçraması neyi gösterir?**
3. **Throughput Graph'da ani düşüş ne anlama gelir?**
4. **RTT Graph'da yüksek değer neyi gösterir?**
5. **Window Scaling Graph'da sıfır window ne demektir?**
6. **IO Graph'da birden fazla satıra farklı display filter uygulanabilir mi?**
7. **Slow Start hangi grafikte exponential büyüme olarak görünür?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **IO Graph tüm paketlerin zaman içindeki dağılımını gösterir (genel). TCP Stream Graph tek bir TCP akışının detaylı analizini gösterir (özel). IO Graph birden fazla filtre satırı alabilir, TCP Stream Graph seçili stream'e odaklanır.**

2. **Retransmission'ı gösterir. Aynı seq no tekrar gönderildiği için grafikte geri sıçrama olur. Normal akış düz veya artan bir çizgidir.**

3. **Paket kaybı, retransmission veya ağ tıkanıklığı olduğunu gösterir. Throughput düşüşü genellikle congestion control'ün devreye girdiği anlamına gelir.**

4. **Ağ gecikmesi (latency) olduğunu gösterir. RTT < 1 ms = aynı switch, 1-10 ms = aynı DC, 10-50 ms = metropol, 50-150 ms = kıtalararası.**

5. **Alıcının buffer'ının tamamen dolduğunu ve daha fazla veri alamayacağını gösterir. Flow control mekanizması devrededir.**

6. **Evet. Her satıra ayrı bir display filter yazılabilir. Bu sayede farklı protokollerin veya trafik türlerinin dağılımı aynı grafikte karşılaştırılabilir.**

7. **Time-Sequence Graph'da Slow Start exponential büyüme olarak görünür (eğri artan çizgi). Throughput Graph'da da exponential artış görülür.**

</details>

---

**Önceki Modül:** [Gelişmiş Capture](../module-18-advanced-capture/module-18-advanced-capture.md)

**Sonraki Modül:** [Performans Analizi](../module-20-performance/module-20-performance.md)
