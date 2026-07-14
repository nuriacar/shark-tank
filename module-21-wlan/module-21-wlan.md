# Modül 21: WLAN Analizi

**Neden?** Ofiste Wi-Fi kopuyor, sürekli yeniden bağlanıyorsun. Deauth attack olabilir. Kablosuz ağlar Ethernet'ten daha kırılgandır: Evil twin (sahte AP), deauth attack (Wi-Fi bağlantısını kesme), WPA2 KRACK (anahtar yeniden kullanımı), PMKID attack (router şifre kırma), beacon flood, probe request tracking. WLAN analizi bu saldırıların tümünü tespit edebilir. Bu modül: kablosuz saldırıları Wireshark ile tespit etmek.

**Görev:** 802.11 kablosuz ağ trafiğini analiz et.

**Öğrenim Hedefleri:**
- 802.11 frame tiplerini (Management, Control, Data) ve alt tiplerini ayırt edebilmek
- Beacon/Probe Request/Response ile AP ve istemci keşfini anlamak
- Authentication/Association sürecini adım adım takip edebilmek
- Deauth saldırısı ve Evil Twin tespiti yapabilmek
- WPA/WPA2 4-way handshake'i analiz edebilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **802.11** | IEEE 802.11: kablosuz yerel alan ağları (WLAN/Wi-Fi) için standart. Ethernet (802.3) kablolu ağlar için nasıl standartsa, 802.11 de kablosuz ağlar için aynı görevi üstlenir. 802.11 frame yapısı Ethernet frame'inden farklıdır: 4 adres alanı taşır (Ethernet 2), frame başlığı 30-34 byte'dır (Ethernet 14 byte). 802.11 frame'leri üç ana kategoriye ayrılır: Management (ağ keşfi ve bağlantı yönetimi), Control (çarpışma önleme ve onay), Data (kullanıcı verisi). Wireshark'ta `wlan` filtresi ile 802.11 trafiği görüntülenir. Kablosuz capture için monitör modunda bir ağ kartı gerekir. |
| **Beacon** | Wi-Fi erişim noktasının (AP) periyodik olarak yayınladığı duyuru çerçevesi. Beacon frame'inde ağ adı (SSID), AP'nin MAC adresi (BSSID), kullanılan kanal (channel), desteklenen hızlar ve güvenlik protokolü (WPA2/WPA3) bulunur. AP'ler genellikle her 102.4 ms'de (100 TU) bir Beacon gönderir. Bir telefon Wi-Fi ağlarını tararken gördüğü liste, bu Beacon frame'lerinden gelir. Wireshark'ta `wlan.fc.type == 0 && wlan.fc.subtype == 8` filtresiyle görüntülenir. Saldırganlar sahte Beacon'lar (Evil Twin) veya çok sayıda Beacon (Beacon flood) göndererek saldırı yapabilir. |
| **SSID** | Service Set Identifier: bir kablosuz ağın adı. Kullanıcıların telefonunda veya bilgisayarında gördüğü Wi-Fi ağ adıdır (örn. "Shark-Tank-Corp"). SSID, Beacon frame'leri içinde yayınlanır. 1-32 karakter uzunluğunda olabilir ve gizlenebilir (hidden SSID); gizli ağlarda Beacon'da SSID alanı boş bırakılır. BSSID (Basic Service Set Identifier) ise AP'nin MAC adresidir ve aynı SSID'ye sahip birden fazla AP'yi birbirinden ayırmak için kullanılır. |
| **Deauthentication (Deauth)** | Bir Wi-Fi cihazının ağla bağlantısını zorla kesen 802.11 management frame'i. Normalde bir istemci ayrılırken gönderilir, ama saldırganlar bunu kötüye kullanır: sahte deauthentication frame'leri göndererek bir cihazı ağdan koparır. Cihaz kopunca yeniden bağlanmaya çalışır ve bu sırada WPA2 4-way handshake'i yakalanabilir (şifre kırma için). Wireshark'ta `wlan.fc.type == 0 && wlan.fc.subtype == 12` filtresiyle görüntülenir. Çok sayıda deauth frame'i bir deauth saldırısını (DoS) gösterir. |
| **WPA handshake** | Wi-Fi Protected Access: kablosuz ağda şifreleme anahtarının oluşturulduğu el sıkışma süreci. WPA2'de bu sürece "4-way handshake" denir: AP ve istemci, önceden paylaşılan şifreden (PSK) türetilen PMK anahtarını kullanarak oturum anahtarlarını (PTK, GTK) dört mesajla değiş tokuş eder. Bu dört mesaj yakalanırsa, şifre çevrimdışı brute-force ile kırılabilir. Wireshark'ta EAPOL frame'leri olarak görünür (`eapol` filtresi). WPA3'te bu süreç SAE (Simultaneous Authentication of Equals) ile değiştirilmiş ve çevrimdışı kırma girişimlerine karşı dayanıklı hale getirilmiştir. |

## Teori

| Tip | Alt Tip | Açıklama |
|-----|---------|----------|
| **Management** (0) | Beacon (8) | AP periyodik duyuru (SSID, BSSID, channel) |
| | Probe Request/Response (4/5) | İstemci keşfi |
| | Association (0/1) | Bağlantı kurma |
| | Authentication (11) | Kimlik doğrulama |
| | Deauthentication (12) | Bağlantı kesme (saldırı!) |
| **Control** (1) | RTS/CTS (11/12) | Çarpışma önleme |
| | ACK (13) | Frame onayı |
| **Data** (2) | Data (0) | Kullanıcı verisi |
| | QoS Data (8) | Öncelikli veri |

### 802.11 vs Ethernet:

| Özellik | 802.11 (WiFi) | Ethernet |
|---------|--------------|----------|
| **Medya** | Paylaşımlı (hava) | Switch (noktadan noktaya) |
| **Frame başlığı** | 30-34 byte | 14 byte |
| **Adres sayısı** | 4 adres alanı | 2 adres (MAC) |
| **Çarpışma** | CSMA/CA (önleme) | CSMA/CD (tespit) |
| **Güvenlik** | WEP/WPA/WPA2/WPA3 | Genelde yok (port-based) |
| **Yönetim** | Management frame'ler | Yok |

### Management Frame'ler:

```
Radio Tap Header          ← Sinyal gücü, channel, rate
  802.11 Beacon Frame     ← SSID: "Shark-Tank-Corp"
    Timestamp
    Beacon Interval: 100 TU (102.4 ms)
    Capabilities: ESS, Privacy
    SSID: "Shark-Tank-Corp"
    Supported Rates: 1, 2, 5.5, 11, 12, 24 Mbps
    DS Parameter Set: Channel 6
    Vendor Specific: WPA/WPA2
```

---

## Hazırlık

Pcap dosyası `shared/pcaps/` içinde hazırdır. İhtiyaç olursa yeniden üretmek için:

```bash
# Otomatik indir + yönetim çerçeveleri ekle:
./scripts/download-sample-pcaps.sh
```

Dosya: `shared/pcaps/module-21-wlan.pcap` (WPA-EAP TLS + yönetim çerçeveleri)

> **Önemli Not: WLAN Capture Sınırlaması:** Bu pcap Wireshark'ın resmi örnek capture'ından indirilmiş ve sentetik yönetim çerçeveleri eklenmiştir. Gerçek bir WLAN analizi için fiziksel bir Wi-Fi adaptörü ve **monitor mode** gereklidir. Docker ortamında Wi-Fi adaptörü ve monitor mode çalışmaz. Kendi ağınızda WLAN capture yapmak için:
>
> **Donanım:** Monitor mode destekleyen bir USB Wi-Fi adaptörü (Alfa AWUS036ACH, TP-Link TL-WN722N v1, veya AirPcap).
>
> **Yazılım:**
> ```bash
> # Linux: airmon-ng ile monitor mode'a geç
> sudo airmon-ng start wlan0
> # Wireshark'ta wlan0mon arayüzünü seç
>
> # macOS:Airport utility
> sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en0 sniff 6
> # 6 = channel numarası
>
# Windows: AirPcap NX veya Npcap + monitor mode destekleyen adaptör
> ```
>
> **WLAN Capture Kaynakları:**
>
> - [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures#Wireless): çeşitli WLAN pcap örnekleri
> - [Kismet](https://www.kismetwireless.net/): profesyonel WLAN sniffer
> - [Aircrack-ng](https://www.aircrack-ng.org/): WLAN güvenlik denetimi araç seti

---

## Alıştırma 1: Beacon Frame Analizi

Beacon frame'ler, AP'nin varlığını duyurduğu periyodik paketlerdir.

### Filtre:
```
wlan.fc.type_subtype == 8
```

### Adımlar:

1. 802.11 pcap'i Wireshark'ta açın
2. Filtre: `wlan.fc.type_subtype == 8`
3. Bir Beacon frame'i seçin ve inceleyin:

```
v IEEE 802.11 Beacon Frame
    v Tagged parameters
        SSID: "Shark-Tank-Corp"          ← Ağ adı
        Supported Rates: 12, 18, 24 Mbps
        DS Parameter Set: Channel 6  ← Kanal
        v Vendor Specific: WPA
            WPA Version: 1           ← WPA/WPA2
```

### Beacon'dan Çıkarılacak Bilgiler:

| Alan | Anlamı |
|------|--------|
| **SSID** | Ağ adı |
| **BSSID** | AP MAC adresi |
| **Channel** | Kullanılan kanal |
| **Supported Rates** | Desteklenen hızlar |
| **Beacon Interval** | 100 TU (genelde) |
| **WPA/WPA2** | Güvenlik tipi |
| **RSN** | Robust Security Network |

> **SINAV İPUÇLARI:**
>
> - Beacon frame = periyodik AP duyurusu (genelde her 102.4 ms)
> - SSID ve BSSID bu frame'den öğrenilir
> - Channel bilgisi DS Parameter Set'te bulunur
> - Güvenlik tipi (WEP/WPA/WPA2) beacon'da belirtilir

---

## Alıştırma 2: Probe Request/Response

İstemci, AP'leri keşfetmek için Probe Request gönderir.

### Filtre:
```
wlan.fc.type_subtype == 4 || wlan.fc.type_subtype == 5
```

### Adımlar:

1. Probe Request (tip 4):
   - İstemci MAC adresini bul
   - Hangi SSID'yi soruyor? (broadcast veya spesifik)
   - Desteklenen hızlar neler?
2. Probe Response (tip 5):
   - Hangi AP cevap verdi?
   - Beacon ile aynı bilgileri içerir

> **SINAV İPUÇLARI:**
>
> - Probe Request = istemci keşfi
> - Probe Response = AP'nin cevabı
> - Broadcast Probe: "Herhangi bir AP var mı?"
> - Directed Probe: "X AP'si var mı?"

---

## Alıştırma 3: Authentication ve Association

İstemci AP'ye bağlanma süreci.

### Filtre:
```
wlan.fc.type_subtype == 11 || wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1
```

### Bağlantı Süreci:

```
İstemci                      AP
  |--- Auth (Open System) --->|    1. Kimlik doğrulama
  |<-- Auth (Open System) ----|    2. Kabul
  |--- Assoc Request -------->|    3. Bağlantı isteği
  |<-- Assoc Response -------|    4. Onay (AID verilir)
  |=== Data frame'ler ====|
  |--- Deauth (Saldırı!) ---->|    5. (Kötü: deauth saldırısı)
```

### Adımlar:

1. Auth frame'leri bulun
2. Association Request'te hangi parametreler var?
3. Association Response'da AID (Association ID) kaç?

> **SINAV İPUCULARI:**
>
> - Auth → Assoc → Data sırası takip edilir
> - Deauth frame = bağlantı kesme (saldırgan tarafından kullanılabilir)
> - AID = AP'nin istemciye verdiği ID

---

## Alıştırma 4: Deauth Saldırısı Tespiti

Deauthentication frame, istemciyi AP'den koparmak için kullanılır.

### Filtre:
```
wlan.fc.type_subtype == 12
```

### Adımlar:

1. Deauth frame'leri bulun
2. Kaynak MAC adresi AP mi? (AP'nin kendisi göndermiş gibi görünür)
3. Hedef MAC (istemci) kim?
4. **Reason Code** nedir?
   - 1: Unspecified
   - 2: Previous authentication no longer valid
   - 3: Deauthenticated because sending station is leaving
   - 7: Class 3 frame received from nonassociated station
   - 8: Disassociated because sending station is leaving

### Deauth Saldırısı Tespiti:

```
Saldırgan (spoofed AP MAC)    Hedef İstemci
  |--- Deauth (Reaso: 7) ---->|
  |--- Deauth (Reaso: 7) ---->|
  |--- Deauth (Reaso: 7) ---->|   ← Sürekli deauth = saldırı!
```

> **SINAV İPUÇLARI:**
>
> - Deauth = istemciyi AP'den koparma
> - Saldırgan AP'nin MAC'ini taklit eder (spoof)
> - Sürekli deauth frame = Deauth saldırısı
> - WPA2 bile deauth'a karşı korumasızdır (management frame koruması yok)

> **İstihbarat İşaretleri, Deauth saldırısı:**
>
> - Aynı kaynaktan çok sayıda Deauth = aktif saldırı
> - Saldırgan, WPA/WPA2 handshake yakalamak için deauth kullanır
> - Handshake yakalandıktan sonra offline brute force yapılabilir

---

## Alıştırma 5: WPA/WPA2 Handshake

WPA/WPA2 4-way handshake, kimlik doğrulama sürecidir.

### Filtre:
```
eapol
```

### 4-Way Handshake:

```
AP                              İstemci
  |--- EAPOL (ANonce) -------->|    1. AP'nin nonce'ı
  |<-- EAPOL (SNonce, MIC) ----|    2. İstemcinin nonce + MIC
  |--- EAPOL (GTK, MIC) ------>|    3. GTK gönderimi
  |<-- EAPOL (ACK) ------------|    4. Onay
```

### Adımlar:

1. Filtre: `eapol`
2. 4-way handshake'in 4 paketini de bulun
3. Her paketin tipini belirleyin:
   - Message 1: AP → İstemci (ANonce)
   - Message 2: İstemci → AP (SNonce + MIC)
   - Message 3: AP → İstemci (GTK)
   - Message 4: İstemci → AP (ACK)
4. **Follow → TCP Stream** ile handshake'i görün (EAPOL Ethernet üzerinden gider)

> **SINAV İPUCULARI:**
>
> - EAPOL = 4-way handshake protokolü
> - Message 1: AP'nin nonce'ı (ANonce)
> - Message 2: İstemcinin nonce'ı (SNonce) + MIC (şifre doğrulama)
> - Message 3: GTK (Group Temporal Key)
> - Offline brute force: Message 2'deki MIC kırılmaya çalışılır
> - Wireshark, EAPOL frame'lerini otomatik tanır

### 802.11 Frame Type/Subtype Filtre Referansı:

Wireshark'ta her frame tipi `wlan.fc.type` ve `wlan.fc.subtype` ile filtrelenir.

| Type | Subtype | Adı | Filtre |
|------|---------|-----|--------|
| 0 (Management) | 0 | Association Request | `wlan.fc.type==0 && wlan.fc.subtype==0` |
| 0 | 1 | Association Response | `wlan.fc.type==0 && wlan.fc.subtype==1` |
| 0 | 4 | Probe Request | `wlan.fc.type==0 && wlan.fc.subtype==4` |
| 0 | 5 | Probe Response | `wlan.fc.type==0 && wlan.fc.subtype==5` |
| 0 | 8 | **Beacon** | `wlan.fc.type==0 && wlan.fc.subtype==8` |
| 0 | 10 | Authentication | `wlan.fc.type==0 && wlan.fc.subtype==10` |
| 0 | 11 | Deauthentication | `wlan.fc.type==0 && wlan.fc.subtype==12` |
| 0 | 12 | **Deauth** | `wlan.fc.type==0 && wlan.fc.subtype==12` |
| 1 (Control) |: | RTS/CTS/ACK | `wlan.fc.type==1` |
| 2 (Data) | 0 | Data | `wlan.fc.type==2 && wlan.fc.subtype==0` |
| 2 | 8 | QoS Data | `wlan.fc.type==2 && wlan.fc.subtype==8` |

> **SINAV İPUCU:** `wlan.fc.type` değerleri: 0=Management, 1=Control, 2=Data. Subtype değerlerini ezberlemek yerine, Wireshark'ın paket detaylarından `wlan.fc.subtype` alanını okuyun ve sağ tık → "Apply as Filter" kullanın.

---

## Alıştırma 6: 802.11 Data Frame ve QoS

Data frame'ler, gerçek kullanıcı verisini taşır.

### Filtre:
```
wlan.fc.type == 2
```

### QoS Data:
```
wlan.fc.type_subtype == 8
```

### Qos Control:

| Bit | Anlamı |
|-----|--------|
| TID (0-7) | Traffic ID (0=BE, 1=BK, 2-3=Voice, 4-5=Video) |
| Ack Policy | Normal / No Ack / Block Ack |

### Adımlar:

1. Data frame'leri bulun
2. QoS data frame'lerinde TID değerini inceleyin
3. Adres alanlarını karşılaştırın:
   - **Address 1**: Receiver (alıcı)
   - **Address 2**: Transmitter (gönderici)
   - **Address 3**: BSSID veya destination/source
   - **Address 4**: Wireless bridge (opsiyonel)

> **SINAV İPUCULARI:**
>
> - 802.11 data frame'de 3-4 MAC adresi bulunur (Ethernet'te 2)
> - QoS = önceliklendirme (Voice/Video yüksek öncelik)
> - TID 0 = Best Effort, TID 6 = Voice

---

## Hızlı Referans - 802.11 Filtreleri

| Filtre | Anlamı |
|--------|--------|
| `wlan.fc.type == 0` | Management frame'ler |
| `wlan.fc.type == 1` | Control frame'ler |
| `wlan.fc.type == 2` | Data frame'ler |
| `wlan.fc.type_subtype == 8` | Beacon |
| `wlan.fc.type_subtype == 4` | Probe Request |
| `wlan.fc.type_subtype == 5` | Probe Response |
| `wlan.fc.type_subtype == 0` | Association Request |
| `wlan.fc.type_subtype == 1` | Association Response |
| `wlan.fc.type_subtype == 11` | Authentication |
| `wlan.fc.type_subtype == 12` | Deauthentication |
| `eapol` | WPA/WPA2 4-way handshake |
| `wlan_radio.signal_dbm` | Sinyal gücü (dBm) |
| `wlan_radio.channel` | Kanal numarası |
| `wlan.bssid` | BSSID (AP MAC) |

---

## Sınav Soruları (Çöz)

1. **802.11'de kaç frame tipi vardır? Hangileridir?**
2. **Beacon frame hangi bilgileri içerir? En az 4 tane sayın.**
3. **WPA/WPA2 4-way handshake hangi filtre ile bulunur?**
4. **Deauth saldırısı nasıl tespit edilir? WPA2 deauth'a karşı korumalı mıdır?**
5. **802.11 data frame'de neden 4 adres alanı bulunur? Ethernet'te neden 2 adres var?**
6. **QoS TID değerleri ne anlama gelir?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **3 tip: Management (0), Control (1), Data (2). Management: Beacon, Probe, Auth, Assoc. Control: RTS/CTS, ACK. Data: kullanıcı verisi.**

2. **SSID (ağ adı), BSSID (AP MAC), Channel, Supported Rates, Beacon Interval, WPA/WPA2 güvenlik tipi, RSN.**

3. **`eapol` filtresi ile. EAPOL, 4-way handshake'in taşındığı protokoldür.**

4. **Sürekli Deauth frame'leri (wlan.fc.type_subtype == 12) aynı kaynaktan gönderiliyorsa = deauth saldırısı. WPA2, management frame koruması olmadığı için deauth'a karşı korumalı değildir. Bu nedenle deauth saldırısı WPA2/WPA3 ağlarda da çalışır.**

5. **Kablosuz ağlarda frame'ler farklı yönlerde hareket edebilir: gönderici, alıcı, BSSID, ve kablosuz bridge durumunda 4. adres gerekir. Ethernet'te sadece kaynak ve hedef MAC yeterlidir (noktadan noktaya).**

6. **TID (Traffic ID) 0-7 arası: 0=Best Effort, 1=Background, 2-3=Voice, 4-5=Video, 6-7=Voice/Video yedek. Yüksek TID = yüksek öncelik.**

</details>

---

**Önceki Modül:** [Performans Analizi](../module-20-performance/module-20-performance.md)

**Sonraki Modül:** [VoIP Analizi](../module-22-voip/module-22-voip.md)
