# Modül 22: VoIP Analizi

**Neden?** Şirket santraline ulaşılamıyor: SIP flood yemiş olabilir. VoIP (SIP/RTP) saldırıları kurumsal ağlarda ciddi tehdittir: SIP flood (santrali çökertme), RTP injection (ses akışına müdahale), eavesdropping (görüşmeyi dinleme), caller ID spoofing (sahte arayan), vishing (sesli phishing). VoIP trafiği genellikle izlenmez: saldırgan bunu bilir. Bu modül: SIP/RTP trafiğini analiz etmek.

**Görev:** SIP sinyalleşme ve RTP ses akışını analiz et.

**Öğrenim Hedefleri:**
- SIP mesaj tiplerini (REGISTER, INVITE, ACK, BYE, CANCEL) tanıyıp çağrı akışını takip edebilmek
- RTP akışını ve ses payload'unu Wireshark'ta inceleyebilmek
- Jitter, packet loss ve latency gibi VoIP kalite metriklerini yorumlayabilmek
- SIP flood ve RTP injection saldırılarını tespit edebilmek
- RTP akışını Wireshark ile ses olarak dinleyebilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **SIP** | Session Initiation Protocol: VoIP çağrılarının kurulması, yönetilmesi ve sonlandırılması için kullanılan sinyalleşme protokolü. Port 5060 (UDP veya TCP) kullanır. SIP, HTTP'ye benzer bir istek-yanıt yapısına sahiptir. Bir çağrının temel akışı şöyledir: arayan REGISTER ile sunucuya kayıt olur, INVITE ile aramayı başlatır, karşı taraf 180 Ringing ile çaldığını bildirir, 200 OK ile çağrıyı kabul eder, ACK ile onaylanır, konuşma RTP üzerinden devam eder ve BYE ile çağrı sonlandırılır. SIP mesajları cleartext olarak iletilir; Wireshark ile aranan numara, arayan kim ve konuşma süresi açıkça görülebilir. |
| **RTP** | Real-time Transport Protocol: VoIP ve video konferans gibi gerçek zamanlı uygulamalarda ses ve video verisini taşıyan protokol. UDP üzerinden çalışır ve genellikle 10000-20000 arası dinamik portlar kullanır. RTP, her pakete bir sequence number ve timestamp ekler; bu sayede alıcı paketleri doğru sıraya koyar ve jitter (gecikme dalgalanması) için buffer yapabilir. SIP çağrı kurulduktan sonra asıl ses verisi RTP paketleri içinde iletilir. Wireshark'ta RTP paketleri `rtp` filtresiyle ve `Telephony → RTP → Stream Analysis` aracıyla analiz edilir; hatta ses kaydı bile çıkarılabilir. |
| **UDP** | User Datagram Protocol: bağlantı kurmadan doğrudan veri gönderen hızlı protokol. Handshake yoktur, onay (ACK) beklenmez, kaybolan paketler yeniden gönderilmez. Bu sayede TCP'den çok daha hızlı ve düşük gecikmeli çalışır, ancak güvenilirlik garantisi yoktur. DNS sorguları, video streaming, VoIP ve çevrimiçi oyunlar gibi hızın güvenilirlikten önemli olduğu uygulamalar UDP kullanır. Başlığı (header) sadece 8 byte'tır; TCP'nin minimum 20 byte'ına kıyasla çok daha hafiftir. |
| **jitter** | Bir ağ bağlantısında paketler arası gecikme süresinin dalgalanması (tutarsızlığı). RTP/VoIP trafiğinde kritik bir kalite göstergesidir. Eğer her paket aynı sürede gelirse jitter sıfırdır (mükemmel). Ama bazı paketler 20 ms, bazıları 80 ms gelirse, ses kalitesi bozulur: ses takılır, kesilir. Jitter, ağ tıkanıklığı, farklı yönlendirme yolları veya yetersiz donanım nedeniyle oluşur. Wireshark'ın RTP Stream Analysis aracı jitter değerini grafik olarak gösterir. Jitter'ı azaltmak için alıcı taraf bir jitter buffer (gecikme tamponu) kullanır: paketleri biriktirip düzgün sırada oynatır. |

## Teori

VoIP iki ana protokolden oluşur:

| Protokol | Port | Amaç |
|----------|------|------|
| **SIP** (Session Initiation Protocol) | 5060 UDP/TCP | Çağrı kurma, yönetme, sonlandırma |
| **RTP** (Real-Time Transport Protocol) | 10000-20000 UDP | Ses/video verisi |
| **RTCP** (RTP Control Protocol) | RTP+1 UDP | Kalite istatistikleri |

### SIP Mesaj Tipleri:

| Mesaj | Anlamı |
|-------|--------|
| **REGISTER** | Kullanıcı kaydı (extension → sunucu) |
| **INVITE** | Çağrı başlatma |
| **ACK** | INVITE onayı |
| **BYE** | Çağrı sonlandırma |
| **CANCEL** | Bekleyen çağrıyı iptal |
| **OPTIONS** | Yetenek sorgulama |
| **INFO** | DTMF tonları |

### SIP Response Kodları:

| Kod | Anlamı |
|-----|--------|
| **100 Trying** | Çağrı işleniyor |
| **180 Ringing** | Çağrı çalıyor |
| **200 OK** | Başarılı |
| **401 Unauthorized** | Kimlik doğrulama gerekli |
| **404 Not Found** | Kullanıcı bulunamadı |
| **486 Busy** | Meşgul |
| **603 Decline** | Reddedildi |

### SIP Call Flow (Örnek):

```
1000@172.50.2.100               VoIP (172.50.2.22)           1001@...
  |--- REGISTER --------------->|                                |
  |<-- 401 Unauthorized --------|                                |
  |--- REGISTER (Auth) -------->|                                |
  |<-- 200 OK ------------------|                                |
  |                                                              |
  |--- INVITE (1001) ---------->|                                |
  |<-- 100 Trying --------------|                                |
  |                             |--- INVITE -------------------->|
  |                             |<-- 180 Ringing ---------------|
  |<-- 180 Ringing -------------|                                |
  |                             |<-- 200 OK --------------------|
  |<-- 200 OK ------------------|                                |
  |--- ACK -------------------->|--- ACK ----------------------->|
  |                                                              |
  |==================== RTP SES ================================>|
  |<=================== RTP SES =================================|
  |                                                              |
  |--- BYE -------------------->|--- BYE ----------------------->|
  |<-- 200 OK ------------------|<-- 200 OK --------------------|
```

---

## Hazırlık

```bash
# VoIP servisini başlat
docker compose up -d voip

# Trafiği üret
./scripts/generate-traffic.sh voip
```

---

## Alıştırma 1: SIP REGISTER Analizi

SIP REGISTER, bir extension'ın sunucuya kaydolmasını sağlar.

### Filtre:
```
sip.Method == "REGISTER"
```

### Adımlar:

1. `shared/pcaps/module-22-voip.pcap`'i Wireshark'ta açın
2. Filtre: `sip.Method == "REGISTER"`
3. 1000 extension'ının REGISTER paketini inceleyin:

```
v Session Initiation Protocol (REGISTER)
    v Request-Line: REGISTER sip:172.50.2.22 SIP/2.0
        Method: REGISTER
        Request-URI: sip:172.50.2.22
    v Message Header
        From: <sip:1000@172.50.2.22>
        To: <sip:1000@172.50.2.22>
        Call-ID: ...
        CSeq: 1 REGISTER
        Contact: <sip:1000@172.50.2.100:5060>
        Expires: 3600
    v Authorization: Digest
        username: "1000"
        realm: "voip"
        nonce: ...
        response: ...
```

4. Hangi extension kaydoluyor? (From alanı)
5. Contact adresi nedir? (IP ve port)
6. Authorization var mı? Digest auth nonce değişiyor mu?

> **SINAV İPUCULARI:**
>
> - SIP REGISTER = extension kaydı
> - Contact = extension'ın IP ve port adresi
> - Expires = kayıt süresi (saniye)
> - 401 Unauthorized + REGISTER (Auth) = digest authentication

---

## Alıştırma 2: SIP INVITE ve Call Setup

INVITE, bir çağrı başlatmak için gönderilir.

### Filtre:
```
sip.Method == "INVITE"
```

### Adımlar:

1. Filtre: `sip.Method == "INVITE"`
2. INVITE paketini inceleyin:

```
v Session Initiation Protocol (INVITE)
    v Request-Line: INVITE sip:1001@172.50.2.22 SIP/2.0
        Method: INVITE
        Request-URI: sip:1001@172.50.2.22
    v Message Header
        From: <sip:1000@172.50.2.22>;tag=1000invite
        To: <sip:1001@172.50.2.22>
        Call-ID: ...
        CSeq: 1 INVITE
        Contact: <sip:1000@172.50.2.100:5060>
        Content-Type: application/sdp
    v Session Description Protocol (SDP)
        Session Description Protocol
            v: 0
            o: user 0 0 IN IP4 172.50.2.100
            s: session
            c: IN IP4 172.50.2.100
            t: 0 0
        v Media Description
            m: audio 10002 RTP/AVP 0 101
            a: rtpmap:0 PCMU/8000
            a: rtpmap:101 telephone-event/8000
```

3. **SDP (Session Description Protocol)** içinde:
   - Media type: audio
   - Port: 10002 (RTP için)
   - Codec: PCMU (G.711 μ-law)
   - Clock rate: 8000 Hz

### Call Setup Flow:

```
1000 → VoIP: INVITE 1001
VoIP → 1000: 100 Trying
VoIP → 1001: INVITE 1001
1001 → VoIP: 180 Ringing
VoIP → 1000: 180 Ringing
1001 → VoIP: 200 OK
VoIP → 1000: 200 OK
1000 → VoIP: ACK
```

> **SINAV İPUCULARI:**
>
> - INVITE = çağrı başlatma
> - SDP içinde media tipi, port, codec bilgisi bulunur
> - 180 Ringing = telefon çalıyor
> - 200 OK = çağrı kabul
> - ACK = 200 OK onayı

---

## Alıştırma 3: SIP BYE ve Call Teardown

BYE, çağrıyı sonlandırır.

### Filtre:
```
sip.Method == "BYE"
```

### Adımlar:

1. Filtre: `sip.Method == "BYE"`
2. BYE paketini inceleyin:

```
v SIP/2.0 200 OK
    Status-Line: SIP/2.0 200 OK
    CSeq: 2 BYE
```

3. Hangi taraf BYE gönderdi? (From alanındaki extension)
4. CSeq numarası neden 2? (INVITE'den sonra ikinci komut)

> **SINAV İPUCULARI:**
>
> - BYE = çağrı sonlandırma
> - Her iki taraf da BYE gönderebilir
> - CSeq her komutta artar

---

## Alıştırma 4: RTP Ses Analizi

RTP, gerçek ses verisini taşır.

### Filtre:
```
rtp
```

### Adımlar:

1. Filtre: `rtp`
2. Bir RTP paketi seçin:

```
v Real-Time Transport Protocol
    v Frame: 1 (Payload: 160 bytes)
        Marker: 0
        Payload type: ITU-T G.711 PCMU (0)
        Sequence number: 1
        Timestamp: 0
        SSRC: 0x...
```

### RTP Header Alanları:

| Alan | Amaç |
|------|------|
| **Payload type** | Codec tipi (0=PCMU, 8=PCMA, 9=G.722) |
| **Sequence number** | Paket sırası (kayıp tespiti) |
| **Timestamp** | Zaman damgası (jitter hesaplama) |
| **SSRC** | Senkronizasyon kaynağı (caller ID) |
| **Marker** | Frame başlangıcı |
| **CSRC** | Katkıda bulunan kaynaklar |

### RTP Analizi:

**Statistics → RTP → Show All Streams** ile:

1. RTP stream'leri listelenir
2. Her stream için:
   - SSRC
   - Destination IP:Port
   - Payload type
   - Packet count
   - Lost packets
   - Jitter (ms)

> **SINAV İPUCULARI:**
>
> - RTP = gerçek ses/video
> - Sequence number = paket kaybı tespiti
> - Timestamp = jitter hesaplama
> - Payload type = codec (0=PCMU, 8=PCMA)
> - **Statistics → RTP → Show All Streams** = tüm RTP akışları

---

## Alıştırma 5: RTP Kalite Analizi

RTP istatistikleri, ses kalitesini ölçer.

### Adımlar:

1. **Statistics → RTP → Show All Streams**
2. Bir stream seçin → **Graph Analysis**
3. Grafikte:

```
Jitter (ms)
  ^
  |    ~     ~     ~
  |   ~ ~   ~ ~   ~ ~        <- Düşük jitter = iyi kalite
  |  ~   ~ ~   ~ ~   ~
  | ~     ~     ~     ~
  +--------------------------------> Zaman
```

4. **RTP Stream Analysis** penceresinde:
   - **Total packets**: kaç paket?
   - **Lost packets**: kaç paket kayboldu?
   - **Loss rate**: % kaç?
   - **Max jitter**: maksimum jitter (ms)
   - **Mean jitter**: ortalama jitter (ms)

### VoIP Kalite Kriterleri:

| Metrik | İyi | Orta | Kötü |
|--------|-----|------|------|
| **Loss rate** | < %1 | %1-3 | > %3 |
| **Jitter** | < 20 ms | 20-50 ms | > 50 ms |
| **Latency** | < 150 ms | 150-300 ms | > 300 ms |
| **MOS** (Mean Opinion Score) | > 4.0 | 3.5-4.0 | < 3.5 |

> **SINAV İPUCULARI:**
>
> - MOS (Mean Opinion Score) = 1-5 arası ses kalitesi (5= mükemmel)
> - Jitter = paketler arası gecikme değişimi
> - Jitter buffer = jitter'ı düzeltir (ama gecikme ekler)
> - Packet loss = ses bozulması

---

## Alıştırma 6: Follow SIP Stream

SIP mesajlarının tam akışını görüntüleme.

### Adımlar:

1. Herhangi bir SIP paketine sağ tık → **Follow → UDP Stream**
2. Tüm SIP mesajlarını sırayla görün:

```
REGISTER sip:172.50.2.22 SIP/2.0
SIP/2.0 401 Unauthorized
REGISTER sip:172.50.2.22 SIP/2.0
SIP/2.0 200 OK

INVITE sip:1001@172.50.2.22 SIP/2.0
SIP/2.0 100 Trying
...
```

3. **Statistics → Flow Graph** ile SIP akışını görselleştirin:
   - **Flow Type**: SIP Flows
   - Her mesajın yönünü ve tipini görün

> **SINAV İPUCU:** Follow UDP Stream ile SIP diyalogunun tamamı görülebilir. SIP çağrı akışını anlamak için kullanışlıdır.

---

## Alıştırma 7: Telephony > VoIP Calls (Çağrı Analizi)

Wireshark'ın Telephony menüsü, VoIP çağrılarını otomatik olarak tespit eder ve analiz eder.

### Adımlar:

1. **Telephony > VoIP Calls** menüsünü aç
2. Wireshark pcap içindeki tüm SIP çağrılarını listeler:
   - Çağrıyı başlatan (From)
   - Çağrının hedefi (To)
   - Başlangıç zamanı
   - Süre (Duration)
   - Durum (Completed, Failed, etc.)
   - Paket sayısı

3. Bir çağrı seç ve **Graph** butonuna tıkla:
   - Görsel çağrı akış diyagramı açılır
   - Her SIP mesajı zaman çizelgesinde gösterilir
   - REGISTER → 401 → REGISTER → 200 → INVITE → 100 Trying → 200 OK → ACK → RTP → BYE

4. Bir çağrı seç ve **Flow** butonuna tıkla:
   - Seq. diagram formatında çağrı akışı
   - Client ve Server arasındaki mesajlar oklarla gösterilir

5. **Player** butonuna tıkla:
   - RTP ses akışını çalabilirsin (eğer ses verisi codec'e uygunsa)
   - `Decode` ile WAV formatına export edebilirsin

### Telephony Menü Referansı:

| Menü | İşlev |
|------|-------|
| **Telephony > VoIP Calls** | Tüm SIP çağrılarını listele, flow graph, player |
| **Telephony > SIP Flows** | SIP akışlarını göster |
| **Telephony > RTP > Show All Streams** | Tüm RTP akışlarını listele |
| **Telephony > RTP > Stream Analysis** | Tek bir RTP stream için jitter/loss grafiği |
| **Statistics > Flow Graph** | Tüm trafiğin zaman çizelgesi (SIP + RTP) |

> **SINAV İPUCU:** Telephony > VoIP Calls, Wireshark'ın en güçlü VoIP analiz aracıdır. Çağrı akış diyagramı (Graph) ile tüm SIP sinyalleşmesini görsel olarak takip edebilirsin. Bu, karmaşık çağrı senaryolarını anlamak için en hızlı yoldur.

---

## Hızlı Referans - VoIP Filtreleri

| Filtre | Anlamı |
|--------|--------|
| `sip` | Tüm SIP trafiği |
| `sip.Method == "REGISTER"` | SIP kayıt |
| `sip.Method == "INVITE"` | Çağrı başlatma |
| `sip.Method == "BYE"` | Çağrı sonlandırma |
| `sip.Method == "ACK"` | Onay |
| `sip.Status-Code == 200` | Başarılı yanıt |
| `sip.Status-Code == 401` | Yetkisiz |
| `sip.From contains "1000"` | Belirli extension |
| `rtp` | Tüm RTP trafiği |
| `rtp.p_type == 0` | PCMU codec |
| `rtp.ssrc == 0x...` | Belirli SSRC |

### RTP İstatistik Menüleri:

| Menü | Amaç |
|------|------|
| Statistics → RTP → Show All Streams | Tüm RTP akışları |
| Statistics → RTP → Stream Analysis | Seçili stream analizi |
| Statistics → RTP → Graph Analysis | Jitter/loss grafiği |

> **SINAV İPUCU:** SIP = sinyalleşme (port 5060), RTP = ses (port 10000-20000). İkisi birlikte VoIP'i oluşturur.

> **İstihbarat İşaretleri, VoIP analizi:**
>
> - Bilinmeyen extension'dan REGISTER = yetkisiz erişim
> - Çok sayıda INVITE = SIP tarama veya flood
> - RTP stream'de yüksek kayıp = ses kalitesi sorunu veya tapping
> - SIP BYE olmadan biten çağrı = anormal sonlanma

---

## Sınav Soruları (Çöz)

1. **SIP hangi portta çalışır? RTP hangi port aralığında?**
2. **SIP REGISTER ne işe yarar? Hangi bilgileri içerir?**
3. **INVITE mesajında SDP (Session Description Protocol) hangi bilgileri taşır?**
4. **BYE mesajı ne zaman gönderilir? Hangi taraf gönderebilir?**
5. **RTP header'da hangi alanlar bulunur? En az 4 tane sayın.**
6. **MOS (Mean Opinion Score) nedir? Kaç aralığındadır?**
7. **SIP ile RTP arasındaki fark nedir?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **SIP: 5060 UDP/TCP. RTP: 10000-20000 UDP (dinamik). RTCP: RTP portu + 1.**

2. **Extension'ın IP adresini ve portunu sunucuya kaydeder. From (extension no), Contact (IP:port), Expires (kayıt süresi), Authorization (digest auth) bilgilerini içerir.**

3. **Media tipi (audio/video), RTP port numarası, codec tipi (PCMU, PCMA, G.722), clock rate (8000 Hz).**

4. **Çağrı sonunda gönderilir. Her iki taraf da BYE gönderebilir. CSeq numarası BYE ile artar.**

5. **Payload type (codec), Sequence number (sıra), Timestamp (zaman), SSRC (kaynak), Marker (frame başlangıcı), CSRC (katkıda bulunanlar).**

6. **Mean Opinion Score = ses kalitesi puanı. 1-5 arası: 5=mükemmel, 4=iyi, 3=orta, 2=kötü, 1=çok kötü.**

7. **SIP sinyalleşme protokolüdür: çağrı kurma, yönetme, sonlandırma. RTP gerçek ses/video verisini taşır. SIP kontrol düzlemi, RTP veri düzlemidir.**

</details>

---

**Önceki Modül:** [WLAN Analizi](../module-21-wlan/module-21-wlan.md)

**Sonraki Modül:** [Baseline Analizi](../module-23-baseline/module-23-baseline.md)
