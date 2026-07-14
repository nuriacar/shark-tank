# Modül 13: HTTP Analizi

**Neden?** Web uygulamasına SQL injection yapıldı, kullanıcı veritabanı çalındı. HTTP trafiğinin tamamı şifresizdir: saldırganın gönderdiği payload Wireshark'ta aynen görünür. SQL injection (veritabanı sızdırma), XSS (kullanıcı çalma), path traversal (dosya okuma), HTTP request smuggling (önbellek zehirleme), credential stuffing (POST body'de şifre dener), CSRF (işlem çalma). Bu modül: HTTP saldırılarını paket seviyesinde tespit etmek.

**Görev:** HTTP trafiğini analiz et. GET/POST isteklerini, status kodlarını, credential sızıntısını incele.

**Öğrenim Hedefleri:**
- HTTP GET/POST isteklerini ve response status kodlarını (200, 302, 403, 404) analiz edebilmek
- Cleartext credential sızıntısını POST body'de tespit edebilmek
- HTTP header'larını (Server, User-Agent, Cookie, Content-Type) okuyup yorumlayabilmek
- SQL injection ve XSS saldırı girişimlerini URL parametrelerinde tanıyabilmek
- Wireshark Export Objects ile HTTP içeriğini dışa aktarabilmek
- Follow TCP Stream ve Statistics > HTTP ile HTTP oturumlarını toplu inceleyebilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **HTTP** | HyperText Transfer Protocol: web tarayıcıları ile web sunucuları arasındaki iletişim protokolü. İstemci (browser) bir istek (request) gönderir, sunucu bir yanıt (response) döner. Tüm içerik düz metin (cleartext) olarak iletilir: hiçbir şifreleme yoktur. Bu yüzden Wireshark ile HTTP trafiğini izleyen biri şifreleri, cookie'leri, form verilerini dahil her şeyi açıkça görebilir. Port 80 kullanır. HTTPS, HTTP'in TLS ile şifrelenmiş halidir (port 443). |
| **TCP** | Transmission Control Protocol: internetin güvenilir ve sıralı veri iletimini sağlayan protokol. Veriyi göndermeden önce alıcıyla bağlantı kurar (3-way handshake), gönderdiği her paket için onay (ACK) bekler ve onay gelmeyen paketleri yeniden gönderir (retransmission). Bu mekanizmalar sayesinde veri kaybı olmadan ve gönderim sırasında bozulmadan teslim edilir. Web (HTTP), email (SMTP), dosya transferi (FTP) gibi kritik işlemlerin tamamı TCP üzerinden çalışır. Bağlantı kurma ve onay bekleme yükü nedeniyle UDP'den yavaştır, ama güvenilirlik gerektiğinde tek seçenektir. |
| **HTTP request method** | İstemcinin sunucudan ne istediğini belirten HTTP komutu. GET, bir kaynağı (web sayfası, API yanıtı) okumak için kullanılır ve parametreleri URL'nin sonuna ekler (örn. `/api/data?id=1`). POST, sunucuya veri göndermek için kullanılır ve veriyi gövdede (body) taşır; form gönderimi ve giriş işlemleri POST ile yapılır. PUT bir kaynağı oluşturur veya günceller, DELETE siler, HEAD sadece header bilgilerini ister (body yok). Wireshark'ta `http.request.method == "GET"` veya `"POST"` filtreleriyle bulunur. Güvenlik açısından POST body'leri önemlidir çünkü kullanıcı adı ve şifreler burada cleartext olarak görünür. |
| **HTTP status code** | Sunucunun isteğe verdiği yanıtın sonucunu belirten 3 haneli kod. 2xx başarılı: 200 OK (her şey normal). 3xx yönlendirme: 302 Moved Temporarily (geçici olarak başka URL'ye yönlendir). 4xx istemci hatası: 401 Unauthorized (giriş gerekli), 403 Forbidden (erişim yasak), 404 Not Found (sayfa yok). 5xx sunucu hatası: 500 Internal Server Error. Wireshark'ta `http.response.code == 200` filtresiyle belirli kodlar aranır. Art arda 401 veya 403 yanıtları brute force girişimini, çok sayıda 404 yanıtı ise directory scanning (dizin tarama) saldırısını gösterebilir. |
| **cleartext** | Verinin hiçbir şifreleme uygulanmadan, olduğu gibi (düz metin) iletilmesi. HTTP, FTP, Telnet, SMTP cleartext protokollerdir: ağ trafiğini dinleyen biri (Wireshark, tcpdump) şifreler, mesaj içerikleri ve kişisel verileri açıkça görebilir. HTTPS (HTTP + TLS), veriyi şifreleyerek bu sorunu çözer. Cleartext trafiğin güvenlik riski, Wireshark gibi araçlarla analiz yapmayı da kolaylaştırır: bu yüzden bu laboratuvarda HTTP kullanılarak tüm trafiğin paket seviyesinde görülebilmesi sağlanmıştır. |
| **HTTP header** | HTTP isteğinde veya yanıtında, gövde (body) öncesi gönderilen metadata alanları. İstek header'ları arasında `Host` (hedef sunucu adı), `User-Agent` (istemci uygulaması ve sürümü), `Cookie` (oturum kimliği), `Content-Type` (gövde veri tipi) bulunur. Yanıt header'ları arasında `Server` (sunucu yazılımı ve sürümü), `Content-Length` (gövde boyutu), `Location` (yönlendirme URL'si) bulunur. Header'lar `Ad: Değer` biçiminde yazılır ve her biri ayrı bir satırdadır. Wireshark'ta HTTP katmanı genişletilerek tüm header'lar tek tek görülebilir. |
| **Follow TCP Stream** | Wireshark'ın bir TCP bağlantısındaki tüm veriyi baştan sona tek pencerede gösteren özelliği. Bir HTTP oturumunu, bir FTP transferini veya bir email gönderimini tam olarak görmek için kullanılır. Paket listesindeki herhangi bir pakete sağ tıklayıp "Follow > TCP Stream" seçilerek açılır. İstemcinin gönderdiği veri (request) ve sunucunun yanıtı (response) farklı renklerle ayrılarak görüntülenir. Sınavda credential sızıntısı, SQL injection payload'ı veya email içeriği gibi verileri hızlıca okumak için en kullanışlı araçtır. |

## Teori

HTTP (HyperText Transfer Protocol), web istemci-sunucu iletişim protokolüdür.
- **Request** (istemci -> sunucu): GET, POST, PUT, DELETE, HEAD
- **Response** (sunucu -> istemci): Status code + headers + body
- **Port:** 80 (varsayılan)
- **Düz metin** - Wireshark'ta tüm içerik görünür (şifresiz)

> **İstihbarat İşaretleri, HTTP, OWASP Top 10'un ana sahasıdır:**
>
> - `http.request.method == "POST"` + `http.file_data contains "password"` → **Cleartext credential sızıntısı**
> - URL'de `' OR 1=1 --` → **SQL injection** denemesi
> - URL'de `<script>alert(1)</script>` → **XSS** denemesi
> - `http.response.code == 401` art arda → **Brute force** girişimi
> - `http.user_agent` anormal → **Bot veya otomatize araç** (nmap, sqlmap, curl)

## Hazırlık

```bash
# Ortam çalışıyor olmalı. Değilse:
./scripts/start.sh

# HTTP trafiği üret:
./scripts/generate-traffic.sh http

# Pcap dosyasını aç:
# macOS: open -a Wireshark shared/pcaps/module-13-http.pcap
# Linux: wireshark shared/pcaps/module-13-http.pcap &
# Windows: start wireshark shared/pcaps/module-13-http.pcap
```

## Alıştırma 1: HTTP GET Isteini İncele

### Filtre:
```
http.request.method == "GET"
```

### Ne Yapmalısın?
1. Filtreyi yazıp Enter'a bas
2. Herhangi bir GET paketine tıkla
3. Orta panelde **Hypertext Transfer Protocol** katmanını genişlet
4. Şu alanları bul:

| Alan | Açıklama | Örnek Değer |
|------|----------|-------------|
| Request Method | Hangi HTTP metodu | GET |
| Request URI | Hangi sayfa | /api/data |
| Request Version | HTTP versiyonu | HTTP/1.1 |
| Host | Hedef sunucu | 172.50.2.10 |
| User-Agent | İstemci bilgisi | curl/8.x.x |
| Accept | Beklenen içerik tipi | */* |

### Görsel Rehber:
```
Orta Panel:
 v Hypertext Transfer Protocol
     GET /api/data HTTP/1.1       <-- Request line
     Host: 172.50.2.10            <-- Header
     User-Agent: curl/8.x.x       <-- Header
     Accept: */*                   <-- Header
```

## Alıştırma 2: HTTP Response'yi İncele

### Filtre:
```
http.response
```

### İncelenecek Alanlar:

| Alan | Açıklama | Örnek Değerler |
|------|----------|---------------|
| Status Code | Sonuç kodu | 200, 302, 403, 404 |
| Content-Type | İçerik tipi | text/html, application/json |
| Content-Length | Gövde boyutu (byte) | 1234 |
| Server | Sunucu yazılımı | nginx/1.x.x |

### Status Kodları (Sınavda Çıkabilir):

| Kod | Anlamı | Bizim Örneğin |
|-----|--------|---------------|
| **200** | Başarılı | GET / , GET /api/data |
| **302** | Yönlendirme | GET /redirect |
| **403** | Yasaklı | GET /secret |
| **404** | Bulunamadı | GET /nonexistent |

## Alıştırma 3: POST Isteini İncele

### Filtre:
```
http.request.method == "POST"
```

1. POST paketini bul ve tıkla
2. **Hypertext Transfer Protocol** katmanını genişlet
3. **HTML Form URL Encoded** alanını genişlet
4. Form verilerini gör:

```
 v HTML Form URL Encoded
     Key: username    Value: admin
     Key: password    Value: secret123    <-- BU SINAVDA SORULUR!
```

> **SINAV İPUCU:** HTTP POST ile gönderilen şifreler Wireshark'ta AÇIKÇA görünür!
> HTTP güvenli değildir, bu yüzden HTTPS kullanılır.

## Alıştırma 4: Follow TCP Stream

1. Herhangi bir HTTP paketine **sağ tıkla**
2. **Follow > TCP Stream**
3. Yeni pencerede TÜM konuşmayı göreceksin:

```
GET /api/data HTTP/1.1          <-- İSTEMCİ (kırmızı)
Host: 172.50.2.10
User-Agent: curl/8.x.x
Accept: */*

HTTP/1.1 200 OK                 <-- SUNUCU (mavi)
Server: nginx/1.x.x
Content-Type: application/json
Content-Length: 72

{"status":"ok","data":"hello from shark-tank","server":"web-01"}
```

> **SINAV İPUCU:** `Follow TCP Stream` ile bir HTTP oturumunun tamamını görebilirsin.
> Bu, sınavda bir web uygulamasının ne yaptığını anlamak için EN ÖNEMLİ araçtır.

## Alıştırma 5: HTTP Yönlendirme (302)

### Filtre:
```
http.response.code == 302
```

1. 302 response paketini bul
2. **Location** header'ına bak -> yönlendirilen URL'yi gösterir
3. Ardindan gelen GET paketini bul (aynı TCP stream'de)

```
İSTEMCİ: GET /redirect HTTP/1.1
SUNUCU:  HTTP/1.1 302 Moved Temporarily
         Location: /
İSTEMCİ: GET / HTTP/1.1              <-- Otomatik yönlendirme
SUNUCU:  HTTP/1.1 200 OK
```

## Alıştırma 6: HTTP Nesne Export (Dosya Kurtarma)

HTTP oturumunda transfer edilen dosyaları kurtarma.

### Adımlar:

1. `shared/pcaps/module-13-http.pcap`'i aç
2. **File > Export Objects > HTTP** menüsünü aç
3. Wireshark tüm HTTP response body'lerini otomatik olarak listeler:

| Filename | Content-Type | Size | Host |
|----------|-------------|------|------|
| `/` | text/html | 737 B | 172.50.2.10 |
| `/api/data` | application/json | ... | 172.50.2.10 |
| `/api/users` | application/json | ... | 172.50.2.10 |
| `/large` | text/plain | 3655 B | 172.50.2.10 |

4. Bir nesneyi seç ve **Preview** ile içeriğine bak (tarayıcıda açılır)
5. **Save** ile tek dosyayı kaydet (örn. `/api/data` → JSON dosyası)
6. **Save All** ile tüm nesneleri bir klasöre kaydet

### Export Edilebilen Nesne Tipleri:

| Menü | İçerik | Kullanım |
|------|--------|----------|
| **HTTP** | Web sayfaları, resimler, JSON, dosyalar | Web forensics |
| **SMB** | Paylaşılan klasör dosyaları | File server analizi |
| **DICOM** | Tıbbi görüntüler | Hastane ağı analizi |
| **IMF** | Email mesajları | Email forensics |
| **TFTP** | TFTP ile transfer edilen dosyalar | Config dosyası sızıntısı |

### Forensic Senaryo:
1. `/api/data` response'unu export et
2. JSON içeriğini incele: hangi veriler sızdı?
3. `/api/users` response'unu export et: kullanıcı listesi mi?
4. `/large` endpoint'inden ne geldi? Boyutu ne?

> **SINAV İPUCU:** Export Objects, sınavda "bu pcap'te hangi dosyalar transfer edilmiş?" sorusunun en hızlı cevabıdır. Her dosyayı tek tek Follow TCP Stream ile bulmaya çalışma: Export Objects ile saniyeler içinde listele.

## Alıştırma 7: SQL Injection ve XSS Tespiti

Bu pcap'te saldırgan benzeri şüpheli HTTP istekleri de bulunur:

### SQL Injection:
```
http.request.uri contains "'" || http.request.uri contains "OR"
```

Capture'da bir istek var:
```
GET /api/data?id=1'+OR+1=1-- HTTP/1.1
```

Bu, tipik bir SQL injection denemesidir. `' OR 1=1--` ifadesi SQL sorgusunu manipüle eder:
- Normal: `SELECT * FROM users WHERE id = 1`
- Enjekte: `SELECT * FROM users WHERE id = 1' OR 1=1--`
- `'` ile sorgu kapatılır, `OR 1=1` ile tüm kayıtlar döndürülür, `--` ile kalan sorgu yorum satırı yapılır

### XSS (Cross-Site Scripting):
```
http.request.uri contains "<script>"
```

Capture'da:
```
GET /api/data?search=<script>alert(1)</script> HTTP/1.1
```

Bu, reflected XSS denemesidir. `<script>alert(1)</script>` tarayıcıda çalıştırılırsa JavaScript kodu çalışır.

### Tespit Filtreleri:
```
# SQL injection
http.request.uri contains "SELECT" || http.request.uri contains "UNION" || http.request.uri contains "OR"

# XSS
http.request.uri contains "<script>" || http.request.uri contains "javascript:"

# Şüpheli karakterler
http.request.uri contains "'" || http.request.uri contains "--" || http.request.uri contains "%27"
```

### Ne Yapmalısın?
1. Yukarıdaki filtreleri dene
2. Şüpheli isteklerin tam URL'ini oku (Follow > TCP Stream ile)
3. Hangi endpoint hedef alınmış? (`/api/data`)
4. User-Agent nedir? Otomatize araç mı yoksa normal tarayıcı mı?

> **SINAV İPUCU:** SQL injection ve XSS, OWASP Top 10'da ilk sıralardadır. Wireshark'ta URL parametrelerini okuyarak bu saldırıları tespit edebilirsin.

## Hızlı Referans - HTTP Filtreleri

```
# Tüm HTTP
http

# Sadece istekler
http.request

# Sadece response'lar
http.response

# Belirli bir method
http.request.method == "GET"
http.request.method == "POST"
http.request.method == "PUT"

# Belirli URL
http.request.uri contains "api"
http.request.uri == "/secret"

# Belirli status code
http.response.code == 200
http.response.code == 403
http.response.code == 404

# Header içere göre
http contains "password"
http contains "admin"
http.user_agent contains "curl"

# Content-Type
http.content_type contains "json"
http.content_type contains "html"
```

## Alıştırma 8: Follow > HTTP Stream ve Statistics > HTTP

### Follow HTTP Stream:

TCP Stream yerine HTTP Stream kullanmak daha okunabilir sonuç verir:

1. Bir HTTP paketine sağ tıkla
2. **Follow > HTTP Stream**
3. İstemci (kırmızı) ve sunucu (mavi) ayırarak tam HTTP konuşmasını gösterir
4. "Show data as" ile raw, UTF-8 veya ASCII seç

### Statistics > HTTP > Requests:

1. **Statistics > HTTP > Requests**
2. Tüm HTTP metodlarını ve URL'leri listeler
3. Hangi URL'ye kaç istek gittiğini gösterir

### Statistics > HTTP > Packet Counter:

1. **Statistics > HTTP > Packet Counter**
2. HTTP response code'larına göre paket sayısını gösterir
3. 200, 302, 403, 404 kaçar tane var?

> **SINAV İPUCU:** Statistics > HTTP > Requests ile hangi URL'lere erişildiğini tek seferde görebilirsiniz. Forensic analizde çok kullanışlıdır.

## Sınav Soruları (Çöz)

1. **HTTP GET ile POST arasındaki fark Wireshark'ta nasıl görünür?**
2. **Bir web sitesine giriş yapıldığında kullanıcı adı ve şifre HTTP'de nasıl görünür? Bul ve yaz.**
3. **302 redirect sonrası istemci nereye yönlendirildi?**
4. **En büyük HTTP response body kaç byte? Hangi URL?**
5. **Server header'ına göre web sunucu ne?**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **GET: URL'de parametre, body yok. POST: body'de veri (username=admin&password=secret123 gibi). Wireshark'ta POST body açıkça görünür.**
2. **username=admin, password=secret123 (POST /auth body'sinde cleartext)**
3. **Location: http://172.50.2.10/ (ana sayfaya)**
4. **`/large` endpoint'inden dönen response: Content-Length değerini kontrol edin.**
5. **nginx/[sürüm]: container image'ındaki nginx sürümüne bağlıdır. Server header'ını kontrol edin.**

</details>

---

**Önceki Modül:** [DNS Analizi](../module-12-dns/module-12-dns.md)

**Sonraki Modül:** [FTP Analizi](../module-14-ftp/module-14-ftp.md)