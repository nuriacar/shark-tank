# Modül 14: FTP Analizi

**Neden?** FTP sunucusunda anormal bir hesap görüldü. Brute force ile ele geçirilmiş olabilir. FTP, kullanıcı adı ve şifreyi düz metin olarak gönderir. Saldırgan Wireshark ile FTP oturumunu izleyerek `USER` ve `PASS` komutlarını okur. Anonymous FTP (açık dosya sunucusu), FTP bounce attack (proxy ile port tarama), brute force tespiti FTP analizinin temel konularıdır. Bu modül: FTP oturumlarındaki güvenlik açıklarını bulmak.

**Görev:** FTP oturumunu analiz et. Command/response yapısını, credential sızıntısını, dosya transferini incele.

**Öğrenim Hedefleri:**
- FTP USER/PASS komutlarında cleartext credential'ları okuyabilmek
- Active (PORT) ve Passive (PASV) mod arasındaki farkı anlamak
- FTP response kodlarını (220, 227, 230, 331) yorumlayabilmek
- FTP brute force saldırısını tespit edebilmek
- FTP bounce attack prensibini bilmek

## Terimler

| Terim | Açıklama |
|-------|----------|
| **FTP** | File Transfer Protocol: bir cihazdan diğerine dosya göndermek ve almak için kullanılan protokol. Port 21'de komut (kontrol) bağlantısı, ayrı bir portta da veri bağlantısı olmak üzere iki ayrı TCP bağlantısı kullanır. Tüm komutlar, kullanıcı adı ve şifre dahil, düz metin (cleartext) olarak iletilir: Wireshark ile trafiği izleyen biri giriş bilgilerini açıkça görebilir. Bu güvenlik açığı nedeniyle modern sistemlerde FTP yerine SFTP (SSH üzerinden) veya FTPS (TLS üzerinden) tercih edilir. Ancak eski sistemlerde ve bu laboratuvarda eğitim amaçlı hala FTP kullanılır. |
| **TCP** | Transmission Control Protocol: internetin güvenilir ve sıralı veri iletimini sağlayan protokol. Veriyi göndermeden önce alıcıyla bağlantı kurar (3-way handshake), gönderdiği her paket için onay (ACK) bekler ve onay gelmeyen paketleri yeniden gönderir (retransmission). Bu mekanizmalar sayesinde veri kaybı olmadan ve gönderim sırasında bozulmadan teslim edilir. Web (HTTP), email (SMTP), dosya transferi (FTP) gibi kritik işlemlerin tamamı TCP üzerinden çalışır. Bağlantı kurma ve onay bekleme yükü nedeniyle UDP'den yavaştır, ama güvenilirlik gerektiğinde tek seçenektir. |
| **cleartext** | Verinin hiçbir şifreleme uygulanmadan, olduğu gibi (düz metin) iletilmesi. HTTP, FTP, Telnet, SMTP cleartext protokollerdir: ağ trafiğini dinleyen biri (Wireshark, tcpdump) şifreler, mesaj içerikleri ve kişisel verileri açıkça görebilir. HTTPS (HTTP + TLS), veriyi şifreleyerek bu sorunu çözer. Cleartext trafiğin güvenlik riski, Wireshark gibi araçlarla analiz yapmayı da kolaylaştırır: bu yüzden bu laboratuvarda HTTP kullanılarak tüm trafiğin paket seviyesinde görülebilmesi sağlanmıştır. |
| **active mode** | FTP'de veri bağlantısının sunucudan istemciye doğru (inbound) kurulduğu çalışma modu. İstemci, PORT komutuyla sunucuya "şu IP ve portta dinliyorum, bana bağlan" der ve sunucu port 20'den istemcinin belirttiği porta TCP bağlantısı başlatır. Bu mod, istemcinin bir portu dışarıdan gelen bağlantıya açmasını gerektirir; güvenlik duvarı arkasındaki veya NAT arkasındaki istemcilerde sorun yaratır. Modern FTP istemcilerinin çoğu varsayılan olarak active mode yerine passive mode kullanır. |
| **passive mode** | FTP'de veri bağlantısının istemciden sunucuya doğru (outbound) kurulduğu çalışma modu. İstemci PASV komutunu gönderir, sunucu "şu rastgele porta bağlan" diyerek yanıt verir (227 koduyla). İstemci daha sonra sunucunun belirttiği porta TCP bağlantısı açar. Passive mode, tüm bağlantıların istemciden çıkış yönünde olması nedeniyle güvenlik duvarları ve NAT cihazlarıyla sorunsuz çalışır. Wireshark'ta PASV yanıtındaki 6 sayıdan ilk 4'ü IP adresini, son 2'si de port numarasını (p1 × 256 + p2) verir. |
| **FTP kontrol ve veri bağlantısı** | FTP'nin iki ayrı TCP bağlantısı kullanma özelliği. Kontrol bağlantısı (port 21) komutlar ve yanıtlar için kullanılır: USER, PASS, LIST, RETR gibi komutlar bu bağlantıdan gönderilir ve oturum boyunca açık kalır. Veri bağlantısı ise dosya transferi ve dizin listesi için kullanılır: her dosya transferinde veya LIST komutunda yeni bir TCP bağlantısı açılır ve transfer bitince kapatılır. Wireshark'ta `ftp` filtresi kontrol bağlantısını, `ftp-data` filtresi veri bağlantısını gösterir. İki bağlantı farklı portlar kullandığı için Wireshark bunları ayrı TCP stream'leri olarak görür. |
| **Follow TCP Stream** | Wireshark'ın bir TCP bağlantısındaki tüm veriyi baştan sona tek pencerede gösteren özelliği. Bir HTTP oturumunu, bir FTP transferini veya bir email gönderimini tam olarak görmek için kullanılır. Paket listesindeki herhangi bir pakete sağ tıklayıp "Follow > TCP Stream" seçilerek açılır. İstemcinin gönderdiği veri (request) ve sunucunun yanıtı (response) farklı renklerle ayrılarak görüntülenir. Sınavda credential sızıntısı, SQL injection payload'ı veya email içeriği gibi verileri hızlıca okumak için en kullanışlı araçtır. |

## Teori

FTP (File Transfer Protocol), dosya transferi için kullanılan protokoldür.
- **Port:** 21 (komut), 20 (veri - active mode)
- **Cleartext!** Kullanıcı adı ve şifre açıkça görünür
- **İki mod:** Active ve Passive
- **İki bağlantı:** Kontrol (komut) + Veri (dosya)

### Active Mode:
```
CLIENT                          FTP SERVER (172.50.2.15:21)
  |--- PORT 172,50,2,100,4,210 ->|    "Beni 172.50.2.100:1234'ten dinle"
  |<-- 200 PORT OK -------------|    "Tamam, bağlanıyorum"
  |--- LIST -------------------->|    Dizin listesi iste
  |<-- 150 Opening data -------|    Veri bağlantısı açılıyor
  |=== SERVER:20 → CLIENT:1234 ===|  VERİ BAĞLANTISI (inbound!)
  |<-- 226 Transfer complete ---|    Tamamlandı
```

### Passive Mode:
```
CLIENT                          FTP SERVER (172.50.2.15:21)
  |--- PASV -------------------->|    "Hangi porta bağlanayım?"
  |<-- 227 (172,50,2,15,82,108) -|    "Port 21100'e bağlan"
  |=== CLIENT → SERVER:21100 ====|  VERİ BAĞLANTISI (outbound)
  |--- LIST -------------------->|    Dizin listesi iste
  |<-- 150 Opening data -------|    Veri bağlantısı açılıyor
  |<-- 226 Transfer complete ---|    Tamamlandı
```

### FTP Oturumu:
```
CLIENT                          FTP SERVER (172.50.2.15:21)
  |<-- 220 Welcome -----------|    Sunucu hazır
  |--- USER ftpuser --------->|    Kullanıcı adı
  |<-- 331 Password needed ---|    Şifre gerekli
  |--- PASS ftppass123 ------->|    ŞİFRE (CLEARTEXT!)
  |<-- 230 Login successful --|    Giriş başarılı
  |--- SYST ------------------>|    Sistem tipi
  |<-- 215 UNIX Type ----------|    Yanıt
  |--- PWD ------------------->|    Mevcut dizin
  |<-- 257 "/" ----------------|    Root dizini
  |--- PASV ------------------->|    Passive mode işte
  |<-- 227 (172,50,2,15,82,108)|    Veri portunu söyle
  |--- LIST ------------------->|    Dizin listesi işte
  |<-- 150 Opening data -------|    Veri bağlantısı açıldı
  |<-- (dosya listesi) --------|    Veri transferi
  |<-- 226 Transfer complete --|    Tamamlandı
  |--- QUIT ------------------->|    Çıkış
  |<-- 221 Goodbye -----------|    Hoşça kal
```

### FTP Response Kodları:

| Kod | Anlamı |
|-----|--------|
| **220** | Sunucu hazır (Welcome) |
| **230** | Giriş başarılı |
| **331** | Şifre gerekli |
| **530** | Giriş başarısız |
| **227** | Passive mode (PASV) port bilgisi |
| **150** | Veri bağlantısı açıldı |
| **226** | Transfer tamamlandı |
| **257** | Mevcut dizin (PWD) |

> **İstihbarat İşaretleri, FTP, compliance audit'lerde en çok eleştirilen protokoldür:**
>
> - `ftp.request.command == "USER"` / `"PASS"` → **Cleartext credentials** (PCI-DSS ihlali)
> - `ftp.response.code == 530` art arda → **Brute force** denemesi
> - `ftp.request.command == "PASV"` → Passive mode (veri kanalı ayrı)
> - `ftp.request.command == "RETR"` → Dosya **indirme** (exfiltration olabilir)
> - `ftp.request.command == "STOR"` → Dosya **yükleme** (malware bırakma olabilir)

## Hazırlık

```bash
./scripts/generate-traffic.sh ftp
# macOS: open -a Wireshark shared/pcaps/module-14-ftp.pcap
# Linux: wireshark shared/pcaps/module-14-ftp.pcap &
# Windows: start wireshark shared/pcaps/module-14-ftp.pcap
```

## Alıştırma 1: FTP Login - Cleartext Credentials

### Filtre:
```
ftp.request.command == "USER" || ftp.request.command == "PASS"
```

### Ne Yapmalısın?
1. USER paketini bul ve tıkla
2. FTP katmanını genişlet:

```
 v File Transfer Protocol (FTP)
     Request command: USER
     Request arg: ftpuser               <-- KULLANICI ADI (açık!)
```

3. PASS paketini bul:

```
 v File Transfer Protocol (FTP)
     Request command: PASS
     Request arg: ftppass123            <-- ŞİFRE (açık!)
```

> **SINAV İPUCU:** FTP credentials Wireshark'ta AÇIKÇA görünür!
> Bu, güvenlik açısından çok kritik bir zafiyettir.
> Çözüm: FTPS (FTP over TLS) veya SFTP (SSH File Transfer) kullanmak.

## Alıştırma 2: FTP Command/Response Akışı

### Filtre:
```
ftp
```

Tüm FTP oturumunu incele:
1. **220 Welcome** -> Sunucu mesajı
2. **USER/PASS** -> Kimlik doğrulama
3. **SYST** -> Sunucu işletim sistemi
4. **PWD** -> Mevcut dizin
5. **PASV** -> Passive mode geçiş
6. **LIST** -> Dizin listesi
7. **RETR** -> Dosya indirme
8. **QUIT** -> Oturum kapatma

### Follow TCP Stream:
1. FTP paketine sağ tıkla -> **Follow > TCP Stream**
2. Tam FTP oturumunu göreceksin:

```
220 (vsFTPd 3.0.5)                              <-- SERVER
USER ftpuser                                     <-- CLIENT
331 Please specify the password.                 <-- SERVER
PASS ftppass123                                  <-- CLIENT
230 Login successful.                            <-- SERVER
SYST                                             <-- CLIENT
215 UNIX Type: L8                                <-- SERVER
PWD                                              <-- CLIENT
257 "/"                                          <-- SERVER
PASV                                             <-- CLIENT
227 Entering Passive Mode (172,50,2,15,82,108).   <-- SERVER (port = 82×256+108 = 21100)
LIST                                             <-- CLIENT
150 Here comes the directory listing.            <-- SERVER
226 Directory send OK.                           <-- SERVER
QUIT                                             <-- CLIENT
221 Goodbye.                                     <-- SERVER
```

> **SINAV İPUCU:** FTP command/response numaralarını bilmeniz gerekir.
> 2xx = başarılı, 3xx = daha fazla bilgi gerekli, 5xx = hata.

## Alıştırma 3: Passive Mode Analizi

### Filtre:
```
ftp.response.code == 227
```

PASV response'u:
```
227 Entering Passive Mode (172,50,2,15,82,108).
```

Port hesaplama: `82 * 256 + 108 = 21100`

Yani veri bağlantısı `172.50.2.15:21100` portuna yapılır.

### Veri bağlantısını bul:
```
tcp.dstport == 21100 || tcp.srcport == 21100
```

> **SINAV İPUCU:** PASV response'taki 6 sayı: ilk 4 = IP, son 2 = port.
> Port = (5. sayı * 256) + 6. sayı

## Alıştırma 4: FTP Veri Transferi

FTP'de iki ayrı TCP bağlantısı vardır:

1. **Kontrol bağlantısı**: Port 21 (komutlar)
2. **Veri bağlantısı**: Dinamik port (dosyalar, dizin listesi)

### Filtre ile ayır:
```
# Kontrol (komutlar):
tcp.dstport == 21 || tcp.srcport == 21

# Veri (dosya transferi):
!(tcp.dstport == 21 || tcp.srcport == 21) && ftp-data
```

> **SINAV İPUCU:** FTP'de veri ve kontrol ayrı TCP bağlantılarında gider.

## Alıştırma 5: Active Mode Analizi

Active mode'da, PORT komutu ile istemci server'a hangi IP ve portta dinlediğini söyler. Server daha sonra **kendi port 20'sinden istemciye** veri bağlantısı başlatır.

### PORT Komutu Formatı:
```
PORT h1,h2,h3,h4,p1,p2
  IP = h1.h2.h3.h4
  Port = p1 * 256 + p2

Örnek: PORT 172,50,2,100,4,210
  IP   = 172.50.2.100
  Port = 4 * 256 + 210 = 1234
```

### Active vs Passive Karşılaştırması:

| Özellik | Active (PORT) | Passive (PASV) |
|---------|--------------|----------------|
| **Veri bağlantısı yönü** | Server → Client | Client → Server |
| **Server veri portu** | 20 (kaynak) | Rastgele (hedef) |
| **Client gereksinimi** | Inbound port açık | Sadece outbound |
| **Firewall sorunu** | Evet (inbound engellenir) | Hayır |
| **Güvenlik** | Düşük (gelen bağlantı) | Daha iyi |

### Adımlar:

1. Filtre: `ftp.request.command == "PORT"`
2. PORT komutunun parametrelerini inceleyin:

```
v File Transfer Protocol (FTP)
    Request command: PORT
    Request arg: 172,50,2,100,4,210
```

3. IP adresini hesaplayın:
   - 172,50,2,100 → 172.50.2.100 (istemci IP'si)
4. Port numarasını hesaplayın:
   - 4 * 256 + 210 = 1234
5. Bu bağlantıda server hangi porttan veri gönderecek?
   - Port 20 (FTP veri portu)
6. Active mode'un güvenlik dezavantajı nedir?
   - İstemcinin bir portu inbound bağlantıya açması gerekir
   - Firewall bu bağlantıyı engelleyebilir
   - NAT arkasındaki istemciler çalışmaz

> **SINAV İPUÇLARI:**
>
> - **PORT** = Active mode, **PASV** = Passive mode
> - PORT'ta IP ve port istemci tarafından belirlenir
> - Active mode'da server port 20'den bağlantı başlatır
> - Port hesaplama: `p1 * 256 + p2`
> - Active mode firewall'lar tarafından genellikle engellenir
> - Pasif mode modern FTP'nin varsayılanıdır

> **İstihbarat İşaretleri, Active mode tespiti:**
>
> - PORT komutu görürsen, istemcinin inbound bağlantı kabul ettiğini anlarsın
> - Bu, istemcinin DMZ'de veya firewall arkasında olmadığını gösterebilir
> - Server port 20'den gelen SYN = Active mode veri bağlantısı

## Alıştırma 6: FTP vs HTTP vs HTTPS - Şifre Karşılaştırma

Aynı pcap'de (mixed) hem FTP hem HTTP hem HTTPS varsa:

| Protokol | Credentials Görünür mu? |
|----------|------------------------|
| **FTP** | EVET - USER/PASS açık metin |
| **HTTP** (POST) | EVET - body'de açık metin |
| **HTTPS** | HAYIR - TLS ile şifreli |

> **SINAV İPUCU:** Sınavda "hangi protokolde şifre görünür?" sorusu çıkabilir.

## Hızlı Referans - FTP Filtreleri

```
# Tüm FTP
ftp

# Komutlar
ftp.request.command == "USER"          # Kullanıcı adı
ftp.request.command == "PASS"          # Şifre
ftp.request.command == "LIST"          # Dizin listesi
ftp.request.command == "RETR"          # Dosya indirme
ftp.request.command == "STOR"          # Dosya yükleme
ftp.request.command == "CWD"           # Dizin değiştir
ftp.request.command == "PASV"          # Passive mode
ftp.request.command == "PORT"          # Active mode
ftp.request.command == "QUIT"          # Çıkış
ftp.request.command == "SYST"          # Sistem bilgisi
ftp.request.command == "PWD"           # Dizin

# Response kodları
ftp.response.code == 220               # Welcome
ftp.response.code == 230               # Login OK
ftp.response.code == 331               # Password needed
ftp.response.code == 530               # Login failed
ftp.response.code == 227               # Passive mode
ftp.response.code == 226               # Transfer complete

# İçerik arama
ftp contains "password"
ftp contains "ftpuser"
ftp.request.arg contains "secret"

# FTP veri bağlantısı
ftp-data
```

## Alıştırma 7: Paket İşaretleme (Mark Packet)

Forensic analizde önemli paketleri işaretleyebilirsiniz:

1. **Edit > Mark Packet** (veya Ctrl+M): Seçili paketi işaretler
2. İşaretli paketler siyah arka planla gösterilir
3. **Edit > Mark All Displayed**: Filtrelenmiş tüm paketleri işaretler
4. **Edit > Find Packet > Marked**: İşaretli paketler arasında gezin
5. **Edit > Unmark All Displayed**: Tüm işaretleri kaldır

### Packet Comments (Paket Notları):

1. Bir pakete sağ tıkla → **Packet Comment...**
2. Not ekle: "FTP login credentials tespit edildi: şüpheli"
3. Yorumlu paketler paket listesinde kalem ikonu ile gösterilir
4. **Edit > Packet Comment** ile yorumları düzenle

> **SINAV İPUCU:** Packet Comments, forensic analizde kanıt notlaması için kullanılır. Export ederken yorumlar pcap dosyasına kaydedilir.

### Analyze > Decode As:

Wireshark'ı yanlış tanınan bir protokolü farklı çözümlemeye zorlayabilirsiniz:
1. **Analyze > Decode As...**
2. "Current" sütunundan protokolü değiştirin
3. Örnek: FTP kontrol bağlantısını HTTP olarak çözümlemeyi deneyin (hatalı gösterim)

> **SINAV İPUCU:** Decode As, standart olmayan portlarda çalışan protokolleri tanımak için kullanılır. Örneğin port 8080'de çalışan FTP'yi FTP olarak çözümlemek.

## Sınav Soruları (Çöz)

1. **FTP ile gönderilen kullanıcı adı ve şifre nedir?**
2. **FTP kontrol bağlantısı hangi portta? Veri bağlantısı hangi portta?**
3. **PASV response'da verilen port nedir? (Hesaplayin)**
4. **FTP session kaç farklı TCP bağlantısından oluşur?**
5. **Sunucunun işletim sistemi bilgisi hangi komutla öğrenildi?**
6. **FTP ile dosya transferi sırasında veri hangi protokolle taşınıyor?**
7. **PORT komutu ile PASV komutu arasındaki temel fark nedir?**
8. **PORT komutunda IP ve port nasıl hesaplanır? Örnek: `PORT 172,50,2,100,4,210`**

<details markdown="block">
<summary>Cevapları Göster</summary>

1. **ftpuser / ftppass123**
2. **Kontrol: 21, Veri: PASV port numaraları her bağlantıda değişir. `ftp.response.code == 227` filtresiyle PASV yanıtlarını bulup port hesaplayın.**
3. **PASV port numaraları her bağlantıda değişir. Yanıtın içindeki 6 sayıyı bulun: port = (5. sayı × 256) + 6. sayı**
4. **TCP bağlantı sayısı değişkendir. Statistics > Conversations ile sayın.**
5. **SYST komutu → "UNIX Type: L8"**
6. **TCP (ftp-data). FTP kontrol ve veri ayrı TCP bağlantıları kullanır.**
7. **PORT (Active mode): istemci IP/port söyler, server port 20'den istemciye bağlanır. PASV (Passive mode): server IP/port söyler, istemci server'a bağlanır. Active mode'da inbound bağlantı gerekir, firewall sorunu yaratır.**
8. **IP = h1.h2.h3.h4 = 172.50.2.100. Port = p1 × 256 + p2 = 4 × 256 + 210 = 1234.**

</details>

---

**Önceki Modül:** [HTTP Analizi](../module-13-http/module-13-http.md)

**Sonraki Modül:** [Email Analizi](../module-15-email/module-15-email.md)