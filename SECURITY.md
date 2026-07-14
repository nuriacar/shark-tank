# Güvenlik Politikası

## Güvenlik Açığı Bildirimi

Bu proje bir **eğitim laboratuvarıdır** ve kasıtlı olarak güvenlik açıkları (cleartext FTP, self-signed TLS, SQL injection simülasyonu) içerir. Bu açıklar eğitim amaçlıdır.

## Gerçek Güvenlik Sorunları

Eğer projenin kendisinde (kod, Dockerfile, script'ler) bir güvenlik açığı bulursanız:

1. **GitHub Issues** üzerinden özel olarak bildirin: https://github.com/nuriacar/shark-tank/issues
2. Veya e-posta gönderin (repo sahibinin iletişim bilgilerine bakın)

Lütfen aşağıdaki bilgileri ekleyin:

- Sorunun açıklaması
- Etkilenen dosya(lar)
- Olası çözüm önerisi

## Kapsam Dışında

Aşağıdakiler güvenlik açığı olarak kabul **edilmez** (eğitim amaçlıdır):

- FTP cleartext credentials
- HTTP POST ile cleartext şifre
- IMAP/POP3/SMTP cleartext credentials
- Self-signed TLS sertifikası
- Dovecot SSL kapalı ve plaintext auth
- vsftpd seccomp sandbox kapalı
- SQL injection simülasyonu (UNION SELECT, OR 1=1)
- XSS simülasyonu (script tag payload'ları)
- Port scanning (nmap -sS)
- SYN flood simülasyonu
- C2 beaconing simülasyonu (periyodik HTTP callback)
- DNS exfiltration simülasyonu (base64 subdomain)

## Yanıt Süresi

- Onay: 7 gün içinde
- Düzeltme: 30 gün içinde (kritik seviyeye bağlı olarak)
