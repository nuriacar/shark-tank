# Modül 16: TLS/SSL Analizi

**Neden?** HTTPS olmasına rağmen kullanıcı bilgileri çalınıyor. SSL stripping saldırısı olabilir: HTTPS HTTP'ye düşürülüyor. TLS trafiği şifrelidir, ancak zafiyetleri vardır: self-signed sertifika tespiti, expired sertifika, Heartbleed (CVE-2014-0160: TLS heartbeat ile memory sızdırma). Ayrıca TLS handshake'ten cipher suite, SNI ve sertifika bilgileri okunur. Bu modül: TLS handshake ve sertifika analizi yaparak zafiyetleri bulmak.

**Görev:** TLS handshake'i analiz et. Cipher suite ve sertifikayı incele. Private key ile trafiği deşifre et.

**Öğrenim Hedefleri:**
- TLS handshake adımlarını (ClientHello, ServerHello, Certificate, KeyExchange, Finished) adım adım takip edebilmek
- Cipher suite, TLS versiyonu ve sertifika bilgilerini okuyabilmek
- TLS 1.2 ile TLS 1.3 arasındaki farkları bilmek
- Private key ile TLS trafiğini deşifre edebilmek
- SSL stripping, self-signed sertifika ve Heartbleed gibi TLS zafiyetlerini tespit edebilmek
- Şifrelenmiş TLS verisini (Application Data) tanımak ve HTTP vs HTTPS farkını bilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **TLS** | Transport Layer Security: bir protokolün (genellikle HTTP) verisini uçtan uca şifreleyen güvenlik katmanı. TLS'nin öncülü SSL (Secure Sockets Layer) olduğundan ikisi genellikle birbirinin yerine kullanılır. TLS, şifreleme (encryption), kimlik doğrulama (certificate ile) ve veri bütünlüğü (MAC/hash ile) sağlar. TLS handshake adı verilen el sıkışma aşaması şifresizdir: istemci ve sunucu bu aşamada hangi şifreleme algoritmasının (cipher suite) kullanılacağını, sertifikaları ve anahtar değişim parametrelerini görüşür. Handshake tamamlandıktan sonra tüm uygulama verisi (Application Data) şifrelenir ve Wireshark'ta okunamaz. HTTPS, HTTP'in TLS ile şifrelenmiş halidir (port 443). |
| **TLS handshake** | İstemci ve sunucunun şifreli iletişim için anlaştığı el sıkışma süreci. TLS 1.2'de adımlar şöyledir: istemci ClientHello gönderir (desteklediği şifreleme yöntemlerini listeler), sunucu ServerHello ile yanıtlar (bir yöntem seçer) ve Certificate ile dijital sertifikasını gönderir, ardından anahtar değişimi (KeyExchange) yapılır ve her iki taraf da ChangeCipherSpec ile "artık şifreli konuşacağım" der, Finished mesajlarıyla handshake tamamlanır. TLS 1.3'te bu süreç kısaldı: anahtar değişimi ClientHello/ServerHello içine gömüldü, ayrı KeyExchange adımları kaldırıldı. Handshake tamamlandıktan sonraki tüm paketler Application Data (şifreli) olarak iletilir. |
| **cipher suite** | TLS bağlantısında kullanılacak şifreleme algoritmalarının bileşimi. Bir cipher suite dört bileşen belirler: anahtar değişim algoritması (örn. ECDHE), kimlik doğrulama algoritması (örn. RSA), toplu şifreleme algoritması (örn. AES_256_GCM) ve hash algoritması (örn. SHA384). Örnek: `TLS_RSA_WITH_AES_256_GCM_SHA384`. İstemci, ClientHello'da desteklediği tüm cipher suite'leri listeler; sunucu, ServerHello'da bunlardan birini seçer. Güvenlik açısından zayıf algoritmalar (RC4, DES, 3DES) içeren cipher suite'ler deşifre edilebilir ve kullanılmamalıdır. TLS 1.3 cipher suite isimleri farklıdır (örn. `TLS_AES_256_GCM_SHA384`). |
| **certificate** | TLS'de sunucunun (veya istemcinin) kimliğini doğrulayan dijital belge. Bir sertifika, sahibinin açık anahtarını (public key) ve kimlik bilgilerini (CN, O, C gibi alanlar) içerir ve bu bilgileri bir Certificate Authority (CA) tarafından dijital olarak imzalanır. Tarayıcılar, bir HTTPS sitesine bağlanırken sunucunun sertifikasını kontrol eder: sertifika güvenilir bir CA tarafından imzalanmış mı, süresi dolmamış mı (validity), CN değeri bağlanılan alan adıyla eşleşiyor mu. Eğer eşleşmezse tarayıcı uyarı verir. TLS handshake'inin Certificate adımında Wireshark ile sertifika içeriği (issuer, subject, validity, CN) açıkça görülebilir. |
| **self-signed certificate** | Kendi kendine imzalanmış sertifika: sertifikayı veren (issuer) ile sertifika sahibinin (subject) aynı olduğu sertifika türü. Normalde bir sertifika güvenilir bir CA (Certificate Authority) tarafından imzalanır, ama self-signed sertifikada sunucu kendi sertifikasını imzalar. Bu, tarayıcılarda güven uyarısına yol açar çünkü sertifikanın sahibi bağımsız bir kuruluş tarafından doğrulanmamıştır. Test ve geliştirme ortamlarında yaygındır (bu laboratuvardaki sertifika self-signed'dır). Üretim ortamında self-signed sertifika, MITM (Man-in-the-Middle) saldırısı göstergesi olabilir. Wireshark'ta issuer = subject olarak görülür. |
| **HTTP** | HyperText Transfer Protocol: web tarayıcıları ile web sunucuları arasındaki iletişim protokolü. İstemci (browser) bir istek (request) gönderir, sunucu bir yanıt (response) döner. Tüm içerik düz metin (cleartext) olarak iletilir: hiçbir şifreleme yoktur. Bu yüzden Wireshark ile HTTP trafiğini izleyen biri şifreleri, cookie'leri, form verilerini dahil her şeyi açıkça görebilir. Port 80 kullanır. HTTPS, HTTP'in TLS ile şifrelenmiş halidir (port 443). |

## Teori

TLS (Transport Layer Security), HTTP gibi protokolleri şifreler.
- **Port:** 443 (HTTPS)
- **Şifreli:** Uygulama verisi Wireshark'ta görünmez
- **Ama:** TLS handshake (el sıkışma) aşaması AÇIK görünür

### TLS Handshake Adımları (TLS 1.2):
```
CLIENT                          SERVER
  |--- ClientHello ------------>|    Destekledigi cipher suite'ler, TLS versiyonu
  |<-- ServerHello ------------|    Seçilen cipher suite, sertifika
  |<-- Certificate ------------|    Sunucunun SSL sertifikası
  |<-- ServerKeyExchange ------|    (bazen) Anahtar değişim parametreleri
  |<-- ServerHelloDone --------|    "Ben hazırım, sen devam et"
  |--- ClientKeyExchange ----->|    Premaster secret (şifreli)
  |--- ChangeCipherSpec ------>|    "Artık şifreli konuşacağım"
  |--- Finished (encrypted) -->|    Şifreli onay
  |<-- ChangeCipherSpec -------|    "Ben de şifreli konuşacağım"
  |<-- Finished (encrypted) ---|    Şifreli onay
  |                             |
   |<===== ŞİFRELİ VERI =======>|    Artık tüm veri şifreli
```

> **Not:** Sunucumuz hem TLS 1.2 hem TLS 1.3 destekler. Çoğu curl/openssl istemcisi TLS 1.3'ü tercih eder.
> TLS 1.3'te handshake daha kısadır: ClientHello → ServerHello + EncryptedExtensions + Certificate + Finished → Finished
> TLS 1.3'te ServerKeyExchange ve ClientKeyExchange **yoktur**: anahtar değişimi ClientHello/ServerHello içine gömülüdür.
> Aşağıdaki alıştırmalarda hangi TLS sürümünün gerçekleştiğini Wireshark'tan kontrol edin.

> **İstihbarat İşaretleri, TLS zafiyetleri, modern siber saldırıların merkezindedir:**
>
> - **Self-signed sertifika** = MITM saldırısı olabilir
> - **TLS 1.0 / 1.1** kullanılıyor = Güvenlik açığı (POODLE, BEAST)
> - **Zayıf cipher suite** (RC4, DES, 3DES) = Deşifre edilebilir
> - **Sertifika CN** hedef sunucuyla eşleşmiyor = Phishing veya MITM
> - TLS downgrade (1.3 → 1.2) = **SSL stripping** saldırısı olabilir

## Hazırlık

```bash
./scripts/generate-traffic.sh tls
# macOS: open -a Wireshark shared/pcaps/module-16-tls.pcap
# Linux: wireshark shared/pcaps/module-16-tls.pcap &
# Windows: start wireshark shared/pcaps/module-16-tls.pcap
```

**TLS 1.2 zorlama (decryption için):**
```bash
docker exec shark-tank-client curl --tlsv1.2 --tls-max 1.2 -sk https://172.50.2.13/secure-data
```

## Alıştırma 1: ClientHello Analizi

### Filtre:
```
tls.record.content_type == 22    # Handshake
```

İlk paket ClientHello olmalı. İçindekiler:

```
 v Transport Layer Security
     Content Type: Handshake (22)
     Version: TLS 1.0 (0x0301)          <-- Record layer versiyonu
     v Handshake Protocol: Client Hello
         Version: TLS 1.2 (0x0303)      <-- Desteklenen en yüksek versiyon
         Random: ...                      <-- 32 byte rastgele değer
         Session ID Length: 0
         v Cipher Suites (20 suites)
             TLS_AES_256_GCM_SHA384      <-- Desteklenen şifreleme yöntemleri
             TLS_CHACHA20_POLY1305_SHA256
             TLS_AES_128_GCM_SHA256
             ...
```

### Ne Yapmalısın?
1. Cipher Suites listesini genişlet
2. Kaç farklı cipher suite destekleniyor? Say
3. TLS versiyonu nedir?

> **SINAV İPUCU:** ClientHello'da istemcinin desteklediği TÜM cipher suite'ler listelenir.

## Alıştırma 2: ServerHello + Cipher Suite Seçimi

### ServerHello'u bul (ikinci handshake paketi):

```
 v Handshake Protocol: Server Hello
     Version: TLS 1.2 (0x0303)               <-- veya TLS 1.3 (0x0304)
     Random: ...
     Session ID Length: 32
     Cipher Suite: TLS_AES_256_GCM_SHA384   <-- SEÇİLEN cipher suite
     Compression Method: null
```

> **Not:** TLS 1.3 cipher suite'leri (TLS_AES_256_GCM_SHA384 gibi) TLS 1.2 cipher suite'lerinden farklıdır.
> Eğer TLS 1.2 gerçekleşirse TLS_RSA_WITH_AES_256_GCM_SHA384 gibi bir suite görürsünüz.
> Hangi sürüm olduğunu anlamak için ServerHello'daki Version alanına bakın:
>
> - `TLS 1.3 (0x0304)` = TLS 1.3
> - `TLS 1.2 (0x0303)` = TLS 1.2

> **SINAV İPUCU:** Sunucu ClientHello'daki cipher suite'lerden birini seçer.
> Bu seçim hangi şifreleme algoritmasının kullanılacağını belirler.

## Alıştırma 3: KeyExchange ve Finished Adımları

TLS handshake'inde ClientHello → ServerHello → Certificate'ten sonraki adımlar:

### TLS 1.2 Handshake'te:
```
ServerKeyExchange   (type 12) : Diffie-Hellman parametreleri
ServerHelloDone     (type 14) : Sunucu hazır
ClientKeyExchange   (type 16) : İstemci anahtarını gönderir
ChangeCipherSpec    (content 20): "Artık şifreli konuşacağım"
Finished            (content 22, encrypted): Şifreli onay
```

Filtreler:
```
# ServerKeyExchange
tls.handshake.type == 12

# ClientKeyExchange
tls.handshake.type == 16

# ChangeCipherSpec
tls.record.content_type == 20
```

### TLS 1.3 Farkı:
TLS 1.3'te **ServerKeyExchange** ve **ClientKeyExchange** yoktur! Anahtar değişimi ClientHello/ServerHello içine gömülüdür. Bu nedenle TLS 1.3 handshake'i daha kısadır.

### Ne Yapmalısın?
1. `tls.handshake.type` filtreleriyle her adımı tek tek bul
2. Hangi TLS sürümü kullanılıyor? (Version alanından kontrol et)
3. TLS 1.3 ise: KeyExchange adımlarını göremezsin: bu normaldir!
4. Finished paketini bul: `tls.record.content_type == 22 && frame contains "Finished"`

> **SINAV İPUCU:** TLS 1.2'de 5 handshake adımı (ClientHello, ServerHello, Certificate, KeyExchange, Finished), TLS 1.3'te 3 adım (ClientHello → ServerHello + Certificate → Finished) olabilir.

## Alıştırma 4: Sertifika Analizi

### Certificate paketini bul:

```
 v Handshake Protocol: Certificate
     Certificates Length: XXX
     v Certificate
         signedCertificate
             version: v3
             serialNumber: ...
             v signature (sha256WithRSAEncryption)
             v issuer: C=TR, ST=İstanbul, L=İstanbul, O=Shark-Tank,
                      OU=Network Analysis Lab, CN=secure.shark-tank.local
             v validity
                 notBefore: ...
                 notAfter: ...
             v subject: C=TR, ST=İstanbul, O=Shark-Tank,
                      CN=secure.shark-tank.local
             subjectPublicKeyInfo: ...
```

### Ne Yapmalısın?
1. **Issuer** (veren): Sertifikayı kim verdi? (self-signed = kendi verdiği)
2. **Subject** (sahip): Sertifika kime ait?
3. **Validity**: Sertifika ne zamandan ne zamana geçerli?
4. **CN** (Common Name): Domain adı nedir?

> **SINAV İPUCU:** Self-signed sertifikalarda issuer = subject.
> Güvenilir bir CA (Certificate Authority) tarafından imzalanmamıştır.

## Alıştırma 5: Şifrelenmiş Veri

### Filtre:
```
tls.record.content_type == 23    # Application Data
```

TLS handshake'den sonraki TÜM veri şifrelidir:
```
 v Transport Layer Security
     Content Type: Application Data (23)
     Version: TLS 1.2
     Length: 123
     Encrypted Application Data: 4a3f8b...   <-- ANLAMSIZ HEX
```

> **SINAV İPUCU:** Şifreli veriyi göremezsin! Ama metadata'yı görebilirsin:
>
> - Kaç byte transfer edildi?
> - Hangi yone?
> - Ne kadar sürede?

## Alıştırma 6: HTTP vs HTTPS Karşılaştırma

Capture dosyasinda hem HTTP hem HTTPS trafiği var.

### HTTP:
```
http
```
- Tüm içerik AÇIKÇA görünür (request, response, header, body)

### HTTPS:
```
tls
```
- Sadece handshake görünür, veri ŞİFRELİ

> **SINAV İPUCU:** HTTP vs HTTPS farkı sınavda KESİN çıkar.
> HTTP'de şifreler açık, HTTPS'de şifreli görünür.

## Alıştırma 7: TLS Trafiğini Deşifre Etme (SSLKEYLOGFILE)

Şifreli TLS trafiğini SSL keylog dosyası ile deşifre edeceksin. Bu yöntem TLS 1.2 ve TLS 1.3 için çalışır.

> **Neden private key değil?** Modern TLS (1.2 ECDHE ve TLS 1.3) Perfect Forward Secrecy (PFS) kullanır. PFS ile private key trafiği deşifre edemezsin. Bunun yerine istemcinin yazdığı keylog dosyası kullanılır. Gerçek dünyada tarayıcılarda `SSLKEYLOGFILE` ortam değişkeni ayarlanarak aynı şey yapılır.

**Adım 1:** `shared/pcaps/module-16-tls.pcap` dosyasını Wireshark'ta aç.

**Adım 2:** `Edit > Preferences > Protocols > TLS` menüsüne git.

**Adım 3:** **(Pre)-Master-Secret log file** alanına şu dosyayı seç:
```
shared/certs/sslkeys.log
```

**Adım 4:** "OK" ile pencereyi kapat.

**Adım 5:** Pcap'ı kapat ve tekrar aç (File > Close, File > Open). Wireshark keylog dosyasını okuyarak TLS trafiğini deşifre eder.

**Adım 6:** Artık şu filtreleri kullanabilirsin:
- `http`: Deşifre edilen HTTP isteklerini gör
- `http.request.method == "POST"`: POST body'lerini oku
- `http.response.code`: Status code'ları gör
- `http.file_data contains "secret"`: Şifreli kanalda gizlenen veriyi bul

**Adım 7:** Deşifre edilmiş paketleri incele:
- Application Data paketlerinin içinde artık "Decrypted TLS" katmanı görünür
- HTTP protokolü içeriği tamamen okunabilir
- `/secure-api` endpoint'ine gönderilen POST body'sini oku

> **SINAV İPUCU:** SSLKEYLOGFILE yöntemi TLS decryption için en güvenilir yoldur. Wireshark > Preferences > Protocols > TLS > (Pre)-Master-Secret log file. Private key yöntemi sadece RSA key exchange (PFS olmayan) ile çalışır.

> **Kendi capture'ını oluştur:** İstemcide `SSLKEYLOGFILE=/tmp/keys.log` ortam değişkenini ayarla, trafiği yakala, sonra Wireshark'ta keylog dosyasını göster. Gerçek IR senaryolarında browser memory dump'inden veya malware sandbox'ından keylog elde edilebilir.

## Alıştırma 8: TLS Versiyon Tespiti ve TLS 1.2 vs 1.3 Karşılaştırması

Bu pcap hem TLS 1.2 hem TLS 1.3 bağlantıları içerir. İkisini karşılaştır.

### Filtre:
```
tls.handshake.type == 2    # ServerHello: seçilen cipher ve TLS sürümü burada
```

### Adımlar:
1. ServerHello paketlerini listele
2. Her birinde `tls.handshake.ciphersuite` alanını bul
3. Cipher suite değerinden TLS sürümünü çıkar:

| Cipher | TLS Sürümü | Anlamı |
|--------|-----------|--------|
| `0x1302` (TLS_AES_256_GCM_SHA384) | TLS 1.3 | Modern, hızlı handshake |
| `0xc030` (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) | TLS 1.2 | Daha uzun handshake |

### TLS 1.2 vs TLS 1.3 Handshake Karşılaştırması:

| Özellik | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| Handshake adım sayısı | Daha fazla (7-9 paket) | Daha az (3-5 paket) |
| ServerKeyExchange | Ayrı paket | Yok (gömülü) |
| ClientKeyExchange | Ayrı paket | Yok (gömülü) |
| ChangeCipherSpec | Ayrı paket | Yok (veya sanity check) |
| Certificate şifreli mi? | Hayır (açık) | Evet (şifreli, keylog olmadan görünmez) |
| PFS (Forward Secrecy) | Opsiyonel (ECDHE) | Zorunlu |

### Wireshark'ta Farkı Gör:
1. TLS 1.2 bağlantısında (cipher 0xc030): Certificate paketini görebilirsin (şifresiz)
2. TLS 1.3 bağlantısında (cipher 0x1302): Certificate şifrelidir: keylog olmadan görülemez
3. TLS 1.3'te handshake daha az paketle tamamlanır

> **SINAV İPUCU:** TLS 1.3'te Certificate şifrelidir. Bu yüzden keylog dosyası olmadan sertifika detayları görülemez. TLS 1.2'de ise Certificate açıktır. Ayrıca TLS 1.3'te ChangeCipherSpec ve ayrı KeyExchange paketleri yoktur: anahtar değişimi handshake içine gömülüdür.

Farklı paketlerde TLS versiyonunu kontrol et.

## Alıştırma 9: TLS Zafiyet Tespiti (SSL Stripping, Heartbleed)

Bu pcap'te TLS zafiyeti yoktur, ancak gerçek dünyada tespit yöntemlerini bilmek sınav için kritiktir.

### SSL Stripping (Downgrade Saldırısı)

Saldırgan, HTTPS bağlantısını HTTP'ye düşürür:
1. Kullanıcı `https://site.com` yazmak isterken saldırgan `http://site.com`'e yönlendirir
2. Tüm trafik şifresiz akar, saldırgan her şeyi okur

Tespit:
```
# Aynı sunucuya hem HTTP hem HTTPS bağlantısı: şüpheli
http && ip.addr == 172.50.2.13

# TLS version downgrade (1.3 → 1.2 veya 1.2 → 1.1)
tls.record.version < 0x0303
```

> **SINAV İPUCU:** SSL stripping, HTTPS'yi HTTP'ye düşüren MITM saldırısıdır. HSTS header'ı bu saldırıyı engeller. Wireshark'ta aynı IP'ye hem HTTP hem TLS trafiği görürseniz SSL stripping olabilir.

### Heartbleed (CVE-2014-0160)

OpenSSL'nin heartbeat extension'ındaki bir bellek sızıntısı zafiyetidir:
1. Saldırı, TLS heartbeat request ile yapılır
2. Sunucunun RAM'inden 64KB'ye kadar veri sızdırılabilir
3. Private key'ler, şifreler, kullanıcı oturumları çalınabilir

Tespit:
```
# Heartbeat request
tls.record.content_type == 24

# Anormal heartbeat payload uzunluğu
tls.heartbeat_message.payload_length > 0
```

> **SINAV İPUCU:** Heartbleed, TLS heartbeat'teki buffer over-read zafiyetidir. Wireshark'ta `tls.record.content_type == 24` filtresi heartbeat mesajlarını gösterir. Normal heartbeat çok az yer kaplarken, exploit'te payload length anormal büyüktür.

### Self-Signed Sertifika Tespiti

Self-signed sertifikalarda issuer = subject (kendi kendine imzalanmış):
```
# Sertifika karşılaştırması
tls.handshake.type == 11
```
Wireshark'ın işaretçileri:
- Sertifikanın rengi **sarı** uyarı ile gösterilir
- `ssi` (self-signed issuer) expert bilgisi görünür
- Sertifika zincirinde **CA sertifikası yoktur**

> **SINAV İPUCU:** Self-signed sertifika tespiti:
>
> - Issuer = Subject
> - Sertifika zincirinde sadece 1 sertifika var
> - Wireshark Expert Info'da "Self-Signed Certificate" uyarısı
> - Gerçek dünyada: MITM saldırısı, test ortamı veya IoT cihazı

## Hızlı Referans - TLS Filtreleri

```
# TLS record tipleri
tls.record.content_type == 20    # ChangeCipherSpec
tls.record.content_type == 21    # Alert
tls.record.content_type == 22    # Handshake
tls.record.content_type == 23    # Application Data (şifreli)

# Handshake mesaj tipleri
tls.handshake.type == 1          # ClientHello
tls.handshake.type == 2          # ServerHello
tls.handshake.type == 11         # Certificate
tls.handshake.type == 12         # ServerKeyExchange
tls.handshake.type == 14         # ServerHelloDone
tls.handshake.type == 16         # ClientKeyExchange

# Sertifika bilgileri
tls.handshake.extensions_server_name == "secure.shark-tank.local"

# Cipher suite
tls.handshake.ciphersuite == 0x009D    # TLS_RSA_WITH_AES_256_GCM_SHA384

# Alert
tls.alert_message.level == 2    # Fatal error
```

## TLS Şifre Çözme (Decryption)

Wireshark, TLS trafiğini şifreli halde gösterir. Ama SSLKEYLOGFILE ile şifreyi çözebilirsiniz:

### Yöntem 1: SSLKEYLOGFILE (Tarayıcıdan Key Log)

1. Tarayıcıyı key log dosyası ile başlatın:
   ```bash
   # macOS
   SSLKEYLOGFILE=/tmp/sslkeys.log /Applications/Firefox.app/Contents/MacOS/firefox

   # Linux
   SSLKEYLOGFILE=/tmp/sslkeys.log firefox

   # Windows (PowerShell)
   $env:SSLKEYLOGFILE="C:\temp\sslkeys.log"; Start-Process firefox
   ```
2. Wireshark'ta: **Edit > Preferences > Protocols > TLS**
3. **(Pre)-Master-Secret log filename** alanına `/tmp/sslkeys.log` yazın
4. Artık TLS Application Data paketlerinin içeriği okunabilir!

### Yöntem 2: Private Key ile Çözme

1. **Edit > Preferences > Protocols > TLS > RSA keys list**
2. **Edit** butonuna tıkla → **Add**
3. IP: 172.50.2.13, Port: 443, Protocol: http, Key File: shared/certs/server.key
4. TLS handshake paketlerinin Application Data'sı artık cleartext HTTP olarak görünür

> **SINAV İPUCU:** WCNA sınavı TLS decryption'ı test eder. SSLKEYLOGFILE yöntemi sınavda en çok sorulan konudur. Private key yöntemi sadece RSA key exchange ile çalışır (TLS 1.3'te çalışmaz).

## Sınav Soruları (Çöz)

1. **ClientHello'da istemci kaç farklı cipher suite destekliyor?**
2. **Sunucu hangi cipher suite'i seçti?**
3. **Sertifikanın CN (Common Name) değeri nedir?**
4. **Sertifika self-signed mi? Issuer ve subject'i karşılaştır.**
5. **Şifrelenmiş Application Data paketlerinde kaç byte veri var? İçerik okunabiliyor mu?**
6. **HTTP ve HTTPS arasındaki görünür fark nedir?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **Cipher suite sayısı istemci kütüphanesine bağlıdır. ClientHello'daki Cipher Suites listesini sayın.**
2. **TLS_AES_256_GCM_SHA384 (TLS 1.3) veya TLS_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2): ServerHello'da görünür**
3. **secure.shark-tank.local**
4. **Evet. Issuer = Subject (C=TR, O=Shark-Tank, CN=secure.shark-tank.local)**
5. **Hayır, şifreli. Byte sayısı görülür ama içerik okunmaz.**
6. **HTTP'de tüm içerik cleartext okunur. HTTPS'de sadece TLS handshake görünür, uygulama verisi şifrelidir.**

</details>

---

**Önceki Modül:** [Email Analizi](../module-15-email/module-15-email.md)

**Sonraki Modül:** [tshark CLI](../module-17-tshark/module-17-tshark.md)