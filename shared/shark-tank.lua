-- ══════════════════════════════════════════════════════════════════════
-- SHARK-TANK v1.2 — Jenerik Ağ Breach Analiz Motoru (tshark Lua)
-- ══════════════════════════════════════════════════════════════════════
-- KULLANIM (3 yol — hepsi aynı raporu üretir):
--
-- A) Kolay yol (repo içinde):
--   ./scripts/shark-tank.sh kayit.pcap        # tek pcap
--   ./scripts/shark-tank.sh shared/pcaps      # dizin: her pcap için .md
--                                             #   + campaign.md (ortak IOC)
--   make shark-tank [FILE=...]                # aynı iş, Makefile'dan
--
-- B) Doğrudan tshark (betiksiz, tüm platformlar):
--   tshark -q -X lua_script:shark-tank.lua -r kayit.pcap
--   Windows: tshark.exe -q -X lua_script:C:\ yol\shark-tank.lua -r kayit.pcap
--   Not: çevre değişkenleri SHARK_TANK_PCAP ile verilir (aşağıya bak).
--
-- C) Wireshark GUI içinden (menüden yükleme):
--   1. Kalıcı kurulum: bu dosyayı Lua plugin dizinine kopyala —
--      macOS/Linux : ~/.local/lib/wireshark/plugins/shark-tank.lua
--      Windows     : %APPDATA%\Wireshark\plugins\shark-tank.lua
--                    (veya C:\Program Files\Wireshark\plugins\)
--      Wireshark'ı yeniden başlat; menü: Analyze (veya Tools) >
--      Shark-Tank > Rapor Üret — açık dosyayı tarayıp pencerede gösterir.
--   2. Geçici yükleme (kopyalamadan): Wireshark > File > "Run Lua Script"
--      (macOS: Wireshark menüsü > Run Lua Script; Alternatif: about:luaconfig)
--      > shark-tank.lua seç > herhangi bir pcap aç > menüden raporu üret.
--      Program çıktısı değil GUI penceresi açılır (dosya yazılmaz).
--
-- Çevre değişkenleri (tshark/bash yolları için):
--   SHARK_TANK_PCAP=kayit.pcap   raporun yazılacağı pcap (adı/yeri)
--   SHARK_TANK_JSON=1            pcap yanına .json çıktısı (SIEM'e)
--   SHARK_TANK_QUIET=1           stdout bildirimini kapat
--
-- Çıktı: pcap ile aynı dizinde, aynı adda <pcap-adı>.md bulgu raporu
-- (+ isteğe bağlı <pcap-adı>.json; dizin modunda campaign.md).
-- Anlatım: Modül 29 (repo) / blog: shark-tank m29 - Lua ile Otomasyon
-- Tasarım: Dedektörler desen tabanlıdır; analiz edilen ağa dair hiçbir
-- varsayım yapılmaz — herhangi bir pcap ile çalışır.
-- ══════════════════════════════════════════════════════════════════════

local ST = {}
ST.version = "1.2"

-- ── yardımcılar ────────────────────────────────────────────────────────
local function shallow(f) return f end

local F = {}   -- field extractor'lar
local function fld(name) local ok, x = pcall(Field.new, name); if ok then F[name] = x end return F[name] end

-- alan tanımları (yoksa pcall ile güvenli)
local fi_ip_src, fi_ip_dst, fi_ipv6_src, fi_ipv6_dst
local fi_tcp_stream, fi_tcp_flags, fi_tcp_srcport, fi_tcp_dstport, fi_tcp_len
local fi_udp_srcport, fi_udp_dstport, fi_tcp_analysis_rtt
local fi_eth_src, fi_eth_dst
local fi_dns_qname, fi_dns_resp, fi_dns_rcode, fi_dns_qtype, fi_dns_a, fi_dns_cname
local fi_http_method, fi_http_uri, fi_http_host, fi_http_ua, fi_http_reqline
local fi_http_code, fi_http_ctype, fi_http_clen, fi_http_cookie, fi_http_setcookie
local fi_http_te, fi_http_filedata, fi_http_server, fi_http_referer
local fi_tls_hstype, fi_tls_version, fi_tls_cipher, fi_tls_sni
local fi_krb_msgtype, fi_krb_cname, fi_krb_sname, fi_krb_error
local fi_ldap_mech, fi_ldap_name, fi_ldap_pwd, fi_ldap_time, fi_ldap_size
local fi_ldap_result, fi_ldap_scope, fi_ldap_filter
local fi_smb2_cmd, fi_smb2_status, fi_smb2_path
local fi_ftp_cmd, fi_ftp_arg, fi_ftp_code, fi_ftp_user
local fi_smtp_cmd, fi_smtp_param, fi_pop_user, fi_pop_pass
local fi_imap_req, fi_wlan_subtype, fi_wlan_ssid, fi_wlan_bssid
local fi_radiotap_dbm, fi_sip_method, fi_sip_to, fi_rtp_ssrc
local fi_icmp_type, fi_icmp_code, fi_icmpv6_type, fi_arp_op
local fi_arp_sip, fi_arp_tip, fi_arp_smac, fi_ocsp_status, fi_x509_cn
local fi_frame_protos, fi_arp_dup, fi_tcp_win, fi_dns_txt, fi_frame_caps_len
local fi_tcp_payload, fi_tls_applen, fi_retrans, fi_dupack, fi_zerowin_f, fi_ooo_f
local fi_smb2_tree, fi_ntlm_user, fi_ntlm_dom, fi_samr_src
local fi_smb2_fname, fi_smb2_readlen, fi_smb2_writelen
local fi_krb_etype, fi_icmp_ident, fi_frag_overlap, fi_frag_conflict
local fi_x509_utctime, fi_tls_sigalg

local function init_fields()
  fi_ip_src        = fld("ip.src")
  fi_ip_dst        = fld("ip.dst")
  fi_ipv6_src      = fld("ipv6.src")
  fi_ipv6_dst      = fld("ipv6.dst")
  fi_eth_src       = fld("eth.src")
  fi_eth_dst       = fld("eth.dst")
  fi_tcp_stream    = fld("tcp.stream")
  fi_tcp_flags     = fld("tcp.flags")
  fi_tcp_srcport   = fld("tcp.srcport")
  fi_tcp_dstport   = fld("tcp.dstport")
  fi_tcp_len       = fld("tcp.len")
  fi_udp_srcport   = fld("udp.srcport")
  fi_udp_dstport   = fld("udp.dstport")
  fi_tcp_analysis_rtt = fld("tcp.analysis.ack_rtt")
  fi_dns_qname     = fld("dns.qry.name")
  fi_dns_resp      = fld("dns.flags.response")
  fi_dns_rcode     = fld("dns.flags.rcode")
  fi_dns_qtype     = fld("dns.qry.type")
  fi_dns_a         = fld("dns.a")
  fi_dns_cname     = fld("dns.cname")
  fi_dns_txt       = fld("dns.txt")
  fi_http_method   = fld("http.request.method")
  fi_http_uri      = fld("http.request.uri")
  fi_http_host     = fld("http.host")
  fi_http_ua       = fld("http.user_agent")
  fi_http_reqline  = fld("http.request.line")
  fi_http_code     = fld("http.response.code")
  fi_http_ctype    = fld("http.content_type")
  fi_http_clen     = fld("http.content_length")
  fi_http_cookie   = fld("http.cookie")
  fi_http_setcookie= fld("http.set_cookie")
  fi_http_te       = fld("http.transfer_encoding")
  fi_http_filedata = fld("http.file_data")
  fi_http_server   = fld("http.server")
  fi_http_referer  = fld("http.referer")
  fi_tls_hstype    = fld("tls.handshake.type")
  fi_tls_version   = fld("tls.record.version")
  fi_tls_cipher    = fld("tls.handshake.ciphersuite")
  fi_tls_sni       = fld("tls.handshake.extensions_server_name")
  fi_krb_msgtype   = fld("kerberos.msg_type")
  fi_krb_cname     = fld("kerberos.CNameString")
  fi_krb_sname     = fld("kerberos.SNameString")
  fi_krb_error     = fld("kerberos.error_code")
  fi_ldap_mech     = fld("ldap.mechanism")
  fi_ldap_name     = fld("ldap.name")
  fi_ldap_pwd      = fld("ldap.simple.password")
  fi_ldap_time     = fld("ldap.timeLimit")
  fi_ldap_size     = fld("ldap.sizeLimit")
  fi_ldap_result   = fld("ldap.bindResponse_resultCode")
  fi_ldap_filter   = fld("ldap.filter")
  fi_smb2_cmd      = fld("smb2.cmd")
  fi_smb2_status   = fld("smb2.nt_status")
  fi_smb2_path     = fld("smb2.path")
  fi_ftp_cmd       = fld("ftp.request.command")
  fi_ftp_arg       = fld("ftp.request.arg")
  fi_ftp_code      = fld("ftp.response.code")
  fi_ftp_user      = fld("ftp.user")
  fi_smtp_cmd      = fld("smtp.req.command")
  fi_smtp_param    = fld("smtp.req.parameter")
  fi_pop_user      = fld("pop.user")
  fi_pop_pass      = fld("pop.password")
  fi_imap_req      = fld("imap.request")
  fi_wlan_subtype  = fld("wlan.fc.type_subtype")
  fi_wlan_ssid     = fld("wlan.ssid")
  fi_wlan_bssid    = fld("wlan.bssid")
  fi_radiotap_dbm  = fld("radiotap.dbm_antsignal")
  fi_sip_method    = fld("sip.Method")
  fi_sip_to        = fld("sip.to.user")
  fi_rtp_ssrc      = fld("rtp.ssrc")
  fi_icmp_type     = fld("icmp.type")
  fi_icmp_code     = fld("icmp.code")
  fi_icmpv6_type   = fld("icmpv6.type")
  fi_arp_op        = fld("arp.opcode")
  fi_arp_sip       = fld("arp.src.proto_ipv4")
  fi_arp_tip       = fld("arp.dst.proto_ipv4")
  fi_arp_smac      = fld("arp.src.hw_mac")
  fi_arp_dup       = fld("arp.duplicate-address-detected")
  fi_ocsp_status   = fld("ocsp.certStatus")
  fi_x509_cn       = fld("x509sat.printableString")
  fi_x509_cn2      = fld("x509sat.utf8String")
  fi_frame_protos  = fld("frame.protocols")
  fi_tcp_win       = fld("tcp.window_size_value")
  fi_frame_caps_len= fld("frame.len")
  fi_tcp_payload   = fld("tcp.payload")
  fi_tls_applen    = fld("tls.record.length")
  fi_retrans       = fld("tcp.analysis.retransmission")
  fi_dupack        = fld("tcp.analysis.duplicate_ack")
  fi_zerowin_f     = fld("tcp.analysis.zero_window")
  fi_ooo_f         = fld("tcp.analysis.out_of_order")
  fi_smb2_tree     = fld("smb2.tree")
  fi_ntlm_user     = fld("ntlmssp.auth.username")
  fi_ntlm_dom      = fld("ntlmssp.auth.domain")
  fi_samr_src      = fld("ip.src")
  fi_smb2_fname    = fld("smb2.filename")
  fi_smb2_readlen  = fld("smb2.read_length")
  fi_smb2_writelen = fld("smb2.write_length")
  fi_krb_etype     = fld("kerberos.etype")
  fi_icmp_ident    = fld("icmp.ident")
  fi_frag_overlap  = fld("ip.fragment.overlap")
  fi_frag_conflict = fld("ip.fragment.overlap.conflict")
  fi_x509_utctime  = fld("x509af.utcTime")
  fi_tls_sigalg    = fld("tls.handshake.sig_hash_alg")
end

local function V(ex) if not ex then return nil end local ok, fi = pcall(ex) if ok and fi then return fi.value end return nil end
local function N(ex)
  local v = V(ex)
  if v == nil then return nil end
  if type(v) == "boolean" then return v and 1 or 0 end
  return tonumber(v)
end
-- FT_BYTES / ByteArray değerini ham Lua string'e çevirir (ASCII/binary)
local function RAW(ex)
  if not ex then return nil end
  local ok, fi = pcall(ex)
  if not (ok and fi) then return nil end
  local v = fi.value
  if type(v) == "string" then return v end
  if type(v) == "table" or (type(v) == "userdata" and v.raw) then
    local ok2, s = pcall(function() return v:raw() end)
    if ok2 then return s end
    local ok3, h = pcall(function() return tostring(v) end)
    if ok3 then return (h:gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end)) end
  end
  return tostring(v)
end

-- FT_NONE (bayrak) alanları: varlık = 1, yokluk = 0 (value nil'dir)
local function P(ex)
  if not ex then return 0 end
  local ok, fi = pcall(ex)
  if ok and fi then return 1 end
  return 0
end

-- ═════════════════════════ DURUM ══════════════════════════════════════
local S = {}
local function reset_state()
  S = {
    pkts = 0, first_ts, last_ts, protos = {},
    ip_src = {}, ip_dst = {}, conv = {},   -- conv["a<->b"] = {pkts, bytes, a2b, b2a}
    -- ARP
    arp_req_by_mac = {}, arp_ip_mac = {}, arp_dup = 0, arp_grat = 0,
    arp_req_pairs = {},                    -- "mac->ip" sayaç (sweep)
    -- ICMP
    icmp_types = {}, icmp_redirect_gw = 0,
    -- IPv6/ICMPv6
    icmpv6_types = {}, ra_srcs = {},
    -- TCP
    syn_by_pair = {}, synack_by_pair = {}, handshake_done = {}, rst_by_src = {},
    syn_nocomplete = {}, retrans = 0, dupack = 0, zerowin = 0, ooo = 0,
    tcp_streams = {}, syn_by_src_port = {},
    -- UDP
    udp_ports_by_src = {},
    -- DNS
    dns_q = {}, dns_nxdomain = {}, dns_long_labels = {}, dns_txt_cnt = 0,
    dns_a_map = {}, dns_last_resp_ts = {},
    -- HTTP
    http_reqs = {}, http_codes = {}, creds = {}, sqli = 0, xss = 0, traversal = 0,
    cookies = {}, uas = {}, downloads = {}, chunked = 0,
    http_big_posts = {}, filedata_by_stream = {},
    -- TLS
    tls_versions = {}, tls_ciphers = {}, tls_snis = {}, tls_ch = 0,
    tls_selfsigned = {}, tls_ocsp = {}, tls_cert_cn = {},
    -- Kerberos
    krb_asreq = 0, krb_tgsreq = 0, krb_asrep = 0, krb_errors = {},
    krb_cnames_by_src = {}, krb_snames = {}, krb_tgs_times = {},
    -- LDAP
    ldap_simple = {}, ldap_anon = 0, ldap_gssapi = 0, ldap_result49 = 0,
    ldap_limits = {}, ldap_filters = {},
    -- SMB2
    smb2_cmds = {}, smb2_fail_by_src = {}, smb2_paths = {},
    -- FTP
    ftp_logins = {}, ftp_fails = 0, ftp_ok = 0, ftp_port_args = {},
    ftp_control_peer = {},
    -- Mail
    smtp_from = {}, smtp_to = {}, smtp_auth_b64 = {}, smtp_subjects = {},
    mail_attach = {}, pop_creds = {}, imap_cmds = {},
    -- WLAN
    ssids = {}, wlan_subtypes = {}, deauth = 0, eapol = 0, rssi = {},
    -- VoIP
    sip_methods = {}, rtp_streams = {}, sip_callers = {},
    -- Davranış
    conn_times = {},   -- ["src|dst|dport"] = {t1, t2, ...}
    syn_stream_seen = {},
    -- SMB/AD ek
    smb2_trees = {}, smb2_badname = {}, smb2_last_tree = {}, smb2_last_user = {}, ntlm_users = {}, ntlm_null = 0,
    samr_ops = {}, samr_srcs = {},
    smb2_files = {},     -- [name] = {reads=byte, writes=byte, src}
    krb_etype23 = 0, krb_etype_srcs = {},
    icmp_ident_cnt = {}, icmp_tunnel_hits = {}, icmp_tunnel_bytes = 0,
    frag_overlap_n = 0, frag_conflict_n = 0,
    x509_times = {}, tls_weak_sig = 0, tls_sig_seen = {},
    svcctl_srcs = {},
    http_get_ts = {},  -- host -> ilk GET ts
    dns_get_delta = {},-- {host=.., delta=..}
    big_payloads = {}, -- entropi adayları {stream, src, dst, len, sample}
    dns_entropies = {},
    experts = 0,
  }
end

-- ═════════════════════════ YARDIMCI ═══════════════════════════════════
local function shannon(s)
  if not s or #s == 0 then return 0 end
  local freq, n = {}, #s
  for i = 1, n do local c = s:sub(i,i) freq[c] = (freq[c] or 0) + 1 end
  local H = 0
  for _, c in pairs(freq) do
    local p = c / n
    H = H - p * math.log(p, 2)
  end
  return H
end

-- base64 çözücü (Basic auth / SMTP AUTH için; Lua'da yok)
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64decode(s)
  s = s:gsub("[^" .. B64 .. "=]", "")
  s = s:gsub("\n", ""):gsub("\r", "")
  local out = {}
  for i = 1, #s, 4 do
    local a, b, c, d = s:byte(i), s:byte(i+1), s:byte(i+2), s:byte(i+3)
    if not a or not b then break end
    local n = (B64:find(string.char(a)) - 1) * 262144
      + (B64:find(string.char(b)) - 1) * 4096
    n = n + ((c and B64:find(string.char(c)) and B64:find(string.char(c)) - 1) or 0) * 64
    n = n + ((d and B64:find(string.char(d)) and B64:find(string.char(d)) - 1) or 0)
    out[#out+1] = string.char(math.floor(n / 65536) % 256)
    if c and c ~= string.byte("=") then out[#out+1] = string.char(math.floor(n / 256) % 256) end
    if d and d ~= string.byte("=") then out[#out+1] = string.char(n % 256) end
  end
  return table.concat(out)
end

local function ts_str(t) return string.format("%.6f", t) end

local TLS_VERS = {
  [0x0300] = "SSL 3.0", [0x0301] = "TLS 1.0", [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2", [0x0304] = "TLS 1.3",
  ["771"] = "TLS 1.2", ["772"] = "TLS 1.3", ["770"] = "TLS 1.0", ["769"] = "SSL 3.0",
}
local function tls_ver_name(v)
  if v == nil then return nil end
  return TLS_VERS[v] or TLS_VERS[tostring(v)] or tostring(v)
end

local function inc(t, k, by) t[k] = (t[k] or 0) + (by or 1) end

local function topN(t, n, min)
  local arr = {}
  for k, v in pairs(t) do if not min or v >= (min or 1) then arr[#arr+1] = {k, v} end end
  table.sort(arr, function(a,b) return a[2] > b[2] end)
  local out = {}
  for i = 1, math.min(n or 10, #arr) do out[i] = arr[i] end
  return out
end

-- ═════════════════════════ PAKET İŞLEME ═══════════════════════════════
local function add_conn_time(src, dst, dport, ts, stream)
  -- beacon analizi: her TCP akışının yalnızca İLK SYN'i sayılır
  if stream then
    if S.syn_stream_seen[stream] then return end
    S.syn_stream_seen[stream] = true
  end
  local k = tostring(src) .. "|" .. tostring(dst) .. "|" .. tostring(dport)
  if not S.conn_times[k] then S.conn_times[k] = {} end
  local a = S.conn_times[k]
  a[#a+1] = ts
end

local function analyze_packet(pinfo)
  S.pkts = S.pkts + 1
  local ts = pinfo.rel_ts or 0
  if not S.first_ts then S.first_ts = ts end
  S.last_ts = ts

  local protos = V(fi_frame_protos)
  if protos then
    for p in string.gmatch(tostring(protos), "[^:]+") do S.protos[p] = (S.protos[p] or 0) + 1 end
  end

  local src = V(fi_ip_src) or V(fi_ipv6_src)
  local dst = V(fi_ip_dst) or V(fi_ipv6_dst)
  if src then inc(S.ip_src, tostring(src)) end
  if dst then inc(S.ip_dst, tostring(dst)) end

  local conv_key
  if src and dst then
    local a, b = tostring(src), tostring(dst)
    conv_key = a < b and (a .. "<->" .. b) or (b .. "<->" .. a)
    if not S.conv[conv_key] then S.conv[conv_key] = {pkts=0, a2b=0, b2a=0, a=a, b=b} end
    local c = S.conv[conv_key]
    c.pkts = c.pkts + 1
    if a == tostring(src) then c.a2b = c.a2b + (N(fi_frame_caps_len) or 0)
    else c.b2a = c.b2a + (N(fi_frame_caps_len) or 0) end
  end

  -- ── ARP ──
  local arp_op = N(fi_arp_op)
  if arp_op then
    S.first_arp_ts = S.first_arp_ts or ts
    local smac = tostring(V(fi_arp_smac) or "")
    local sip  = tostring(V(fi_arp_sip) or "")
    local tip  = tostring(V(fi_arp_tip) or "")
    if arp_op == 1 then
      inc(S.arp_req_pairs, smac .. "->" .. tip)
      if sip == tip then S.arp_grat = S.arp_grat + 1 end
    elseif arp_op == 2 then
      if S.arp_ip_mac[sip] and S.arp_ip_mac[sip] ~= smac then
        S.arp_dup = S.arp_dup + 1
      end
    end
    if sip ~= "" and smac ~= "" then
      S.arp_ip_mac[sip] = smac
    end
  end
  if P(fi_arp_dup) == 1 then S.arp_dup = S.arp_dup + 1 end

  -- ── ICMP ──
  local it = N(fi_icmp_type)
  if it then
    inc(S.icmp_types, it)
    if it == 5 then S.icmp_redirect_gw = S.icmp_redirect_gw + 1 end
  end
  local it6 = N(fi_icmpv6_type)
  if it6 then
    inc(S.icmpv6_types, it6)
    if it6 == 134 then inc(S.ra_srcs, tostring(src)) end
  end

  -- ── TCP ──
  local tcpflags = N(fi_tcp_flags)
  local stream = N(fi_tcp_stream)
  local sport, dport = N(fi_tcp_srcport), N(fi_tcp_dstport)
  if tcpflags then
    local SYN, ACK, RST, FIN = (tcpflags & 0x02) ~= 0, (tcpflags & 0x10) ~= 0, (tcpflags & 0x04) ~= 0, (tcpflags & 0x01) ~= 0
    if SYN and not ACK then
      local k = tostring(src) .. "->" .. tostring(dst) .. ":" .. tostring(dport)
      inc(S.syn_by_pair, k)
      local sk = tostring(src)
      S.syn_by_src_port[sk] = S.syn_by_src_port[sk] or {}
      S.syn_by_src_port[sk][dport] = (S.syn_by_src_port[sk][dport] or 0) + 1
      S.syn_nocomplete[k] = true
      S.first_syn_ts = S.first_syn_ts or ts
      add_conn_time(src, dst, dport, ts, stream)
    elseif SYN and ACK then
      local k = tostring(dst) .. "->" .. tostring(src) .. ":" .. tostring(sport)
      if S.syn_nocomplete[k] then S.syn_nocomplete[k] = nil end
      S.handshake_done[k] = true
    elseif ACK and stream then
      S.tcp_streams[stream] = true
    end
    if RST then inc(S.rst_by_src, tostring(src)) end
  end
  -- TCP analiz bayrakları (FT_NONE: varlık kontrolü P() ile)
  if P(fi_retrans) == 1 then S.retrans = S.retrans + 1 end
  if P(fi_dupack) == 1 then S.dupack = S.dupack + 1 end
  if P(fi_zerowin_f) == 1 or N(fi_tcp_win) == 0 then S.zerowin = S.zerowin + 1 end
  if P(fi_ooo_f) == 1 then S.ooo = S.ooo + 1 end

  -- ── UDP ──
  local uport = N(fi_udp_dstport)
  if uport then
    local sk = tostring(src)
    S.udp_ports_by_src[sk] = S.udp_ports_by_src[sk] or {}
    S.udp_ports_by_src[sk][uport] = (S.udp_ports_by_src[sk][uport] or 0) + 1
  end

  -- ── DNS ──
  local qname = V(fi_dns_qname)
  if qname then
    local resp = N(fi_dns_resp)
    if resp == 0 then
      local q = tostring(qname)
      S.dns_q[q] = true
      local labels = {}
      for lab in q:gmatch("[^.]+") do labels[#labels+1] = lab end
      local maxlen = 0
      for _, lab in ipairs(labels) do if #lab > maxlen then maxlen = #lab end end
      if #q > 40 and maxlen >= 30 then
        S.dns_long_labels[#S.dns_long_labels+1] = q
        S.first_dns_tunnel_ts = S.first_dns_tunnel_ts or ts
        S.dns_entropies[#S.dns_entropies+1] = { name = q, H = shannon(q) }
      end
      if N(fi_dns_qtype) == 16 then S.dns_txt_cnt = S.dns_txt_cnt + 1 end
      S.dns_last_resp_ts[q] = ts
    else
      local rcode = N(fi_dns_rcode)
      if rcode == 3 then inc(S.dns_nxdomain, tostring(qname)) end
      local a = V(fi_dns_a)
      if a then S.dns_a_map[tostring(qname)] = tostring(a) end
    end
  end

  -- ── HTTP ──
  local method = V(fi_http_method)
  local uri    = V(fi_http_uri)
  local host   = V(fi_http_host)
  if method then
    local h = host and tostring(host) or "-"
    S.http_reqs[#S.http_reqs+1] = {
      ts = ts, src = tostring(src), dst = tostring(dst), dport = dport,
      method = tostring(method), uri = uri and tostring(uri) or "-", host = h,
    }
    local u = uri and tostring(uri) or ""
    local uu = u:lower()
    if method == "POST" then
      local body = RAW(fi_http_filedata) or ""
      local clen = N(fi_http_clen) or #body
      S.http_big_posts[#S.http_big_posts+1] = {
        ts = ts, src = tostring(src), uri = u, len = clen, stream = stream,
        H = (#body > 64) and shannon(body) or nil,
        looks_b64 = #body > 16 and (body:match("^[A-Za-z0-9+/=\r\n]+$") ~= nil),
      }
      if body:lower():find("password", 1, true) or body:lower():find("passwd", 1, true) or body:lower():find("pass=", 1, true) then
        S.creds[#S.creds+1] = { ts = ts, src = tostring(src), ctx = "HTTP POST " .. u, data = body:sub(1, 160) }
      end
    end
    if method == "GET" and S.dns_last_resp_ts[h] and not S.http_get_ts[h] then
      S.http_get_ts[h] = ts
      S.dns_get_delta[#S.dns_get_delta+1] = { host = h, delta = ts - S.dns_last_resp_ts[h] }
    end
    local uu = u:lower()
    local function hasPlain(hay, needle) return hay:find(needle, 1, true) ~= nil end
    if hasPlain(uu, "union+select") or hasPlain(uu, "union select") or hasPlain(uu, "or+1=1")
      or hasPlain(uu, "or 1=1") or hasPlain(uu, "' or ") or hasPlain(uu, "%27")
      or hasPlain(uu, "sleep(") or hasPlain(uu, "benchmark(") or hasPlain(uu, "information_schema") then S.sqli = S.sqli + 1 end
    if hasPlain(uu, "<script") or hasPlain(uu, "javascript:") or hasPlain(uu, "onerror=")
      or hasPlain(uu, "document.cookie") or hasPlain(uu, "alert(") then S.xss = S.xss + 1; S.first_inject_ts = S.first_inject_ts or ts end
    if hasPlain(uu, "../") or hasPlain(uu, "%2e%2e%2f") or hasPlain(uu, "/etc/passwd") or hasPlain(uu, "..\\") then S.traversal = S.traversal + 1 end
    if u:match("%.zip$") or u:match("%.exe$") or u:match("%.rar$") or u:match("%.7z$") or u:match("%.gz$") then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(src), dst = tostring(dst), uri = u }
    end
    local ua = V(fi_http_ua)
    if ua then
      local u = tostring(ua)
      inc(S.uas, u)
      -- Sahte UA tespiti: eski IE sürümü + modern Windows (gerçek tarayıcıda imkânsız)
      local ie = u:match("MSIE%s+(%d+)")
      local nt = u:match("Windows NT%s+(%d+%.?%d*)")
      if ie and nt then
        local iev, ntv = tonumber(ie), tonumber(nt)
        if iev and ntv and iev <= 9 and ntv >= 10 then
          S.fake_uas = S.fake_uas or {}
          S.fake_uas[#S.fake_uas+1] = { src = tostring(src), ua = u }
        end
      end
    end
  end
  local code = N(fi_http_code)
  if code then inc(S.http_codes, code) end
  local sc = V(fi_http_setcookie)
  if sc then S.cookies[#S.cookies+1] = { dir = "set", src = tostring(src), val = tostring(sc):sub(1,120) } end
  local ck = V(fi_http_cookie)
  if ck then S.cookies[#S.cookies+1] = { dir = "req", src = tostring(src), val = tostring(ck):sub(1,120) } end
  if V(fi_http_te) and tostring(V(fi_http_te)):lower():find("chunked") then S.chunked = S.chunked + 1 end
  local fdata = RAW(fi_http_filedata)
  if fdata and #fdata > 128 then
    local magic = fdata:sub(1, 5)
    if magic:sub(1,4) == "PK\x03\x04" then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(dst), dst = tostring(src), uri = "(gövdeden: ZIP arşivi, PK\\\\x03\\\\x04)", magic = "ZIP" }
    elseif magic:sub(1,2) == "MZ" then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(dst), dst = tostring(src), uri = "(gövdeden: PE çalıştırılabilir, MZ)", magic = "EXE" }
    elseif magic == "%PDF-" then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(dst), dst = tostring(src), uri = "(gövdeden: PDF)", magic = "PDF" }
    elseif magic:sub(1,4) == "\x89PNG" then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(dst), dst = tostring(src), uri = "(gövdeden: PNG resmi)", magic = "PNG" }
    elseif magic:sub(1,3) == "GIF" then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(dst), dst = tostring(src), uri = "(gövdeden: GIF resmi)", magic = "GIF" }
    elseif magic:sub(1,4) == "\x7fELF" then
      S.downloads[#S.downloads+1] = { ts = ts, src = tostring(dst), dst = tostring(src), uri = "(gövdeden: ELF çalıştırılabilir)", magic = "ELF" }
    end
  end

  -- ── TLS ──
  local hstype = N(fi_tls_hstype)
  if hstype then
    if hstype == 1 then
      S.tls_ch = S.tls_ch + 1
      local sni = V(fi_tls_sni)
      if sni then inc(S.tls_snis, tostring(sni)) end
    elseif hstype == 2 then
      local ver = tls_ver_name(V(fi_tls_version))
      if ver then inc(S.tls_versions, ver) end
      local cip = V(fi_tls_cipher)
      if cip then inc(S.tls_ciphers, tostring(cip)) end
    end
  end
  -- not: tüm kayıtların surumu ayri ayri sayilmaz; ServerHello onaylı surum esas alınır (goruntu kirliligi olmasın diye)
  local certcn = V(fi_x509_cn) or V(fi_x509_cn2)
  if certcn and hstype == 11 then
    S.tls_cert_cn[#S.tls_cert_cn+1] = tostring(certcn)
  end
  local ocs = V(fi_ocsp_status)
  if ocs then S.tls_ocsp[#S.tls_ocsp+1] = tostring(ocs) end

  -- ── Kerberos ──
  local kmt = N(fi_krb_msgtype)
  if kmt then
    if kmt == 10 then
      S.krb_asreq = S.krb_asreq + 1
    elseif kmt == 12 then
      S.krb_tgsreq = S.krb_tgsreq + 1
      -- SNameString çoklu örnektir: bileşenleri birleştir, servis bileşenini ayıkla
      local okS, parts = pcall(function()
        local t = { fi_krb_sname() }
        local vals = {}
        for _, fx in ipairs(t) do vals[#vals+1] = tostring(fx.value) end
        return table.concat(vals, "/")
      end)
      if okS and parts then
        -- "krbtgt/REALM/servis/host" biçiminden servis bileşeni
        local seg = {}
        for s in parts:gmatch("[^/]+") do seg[#seg+1] = s end
        local svc = (#seg >= 3) and seg[3] or parts
        inc(S.krb_snames, svc)
        S.krb_tgs_times[#S.krb_tgs_times+1] = ts
      end
    elseif kmt == 11 then S.krb_asrep = S.krb_asrep + 1
    elseif kmt == 30 then
      local ec = V(fi_krb_error)
      S.krb_errors[#S.krb_errors+1] = tostring(ec)
    end
    if kmt == 10 or kmt == 12 then
      local okC, tC = pcall(function() return { fi_krb_cname() } end)
      if okC and tC and tC[1] then
        local cname = tostring(tC[1].value)
        S.krb_cnames_by_src[tostring(src)] = S.krb_cnames_by_src[tostring(src)] or {}
        S.krb_cnames_by_src[tostring(src)][cname] = (S.krb_cnames_by_src[tostring(src)][cname] or 0) + 1
      end
    end
  end

  -- ── LDAP ──
  local mech = V(fi_ldap_mech)
  if mech then
    local m = tostring(mech)
    if m == "simple" then
      local nm, pw = V(fi_ldap_name), V(fi_ldap_pwd)
      S.ldap_simple[#S.ldap_simple+1] = { src = tostring(src), name = nm and tostring(nm) or "-", pass = pw and tostring(pw) or "?" }
    elseif m == "GSSAPI" then S.ldap_gssapi = S.ldap_gssapi + 1
    elseif m == "" or m == "none" then S.ldap_anon = S.ldap_anon + 1 end
  end
  local lres = N(fi_ldap_result)
  if lres == 49 then S.ldap_result49 = S.ldap_result49 + 1 end
  local lt, ls = N(fi_ldap_time), N(fi_ldap_size)
  if (lt and lt > 0) or (ls and ls > 0) then
    S.ldap_limits[#S.ldap_limits+1] = { timeLimit = lt, sizeLimit = ls }
  end
  local lf = V(fi_ldap_filter)
  if lf then S.ldap_filters[#S.ldap_filters+1] = tostring(lf) end

  -- ── SMB2 ──
  local scmd = N(fi_smb2_cmd)
  if scmd then
    inc(S.smb2_cmds, scmd)
    local stv = N(fi_smb2_status)
    if stv == 0xC000006D then
      inc(S.smb2_fail_by_src, tostring(src))
    end
    if scmd == 3 then
      local tree = V(fi_smb2_tree) or V(fi_smb2_path)
      local stv = N(fi_smb2_status)
      -- İstek tree'yi taşır, yanıt status'u: konuşmaya göre eşle (yön-bağımsız anahtar)
      local a, b = tostring(src), tostring(dst)
      local ck = a < b and (a .. "|" .. b .. "|" .. tostring(math.min(sport or 0, dport or 0))) or (b .. "|" .. a .. "|" .. tostring(math.min(sport or 0, dport or 0)))
      if tree then
        local t = tostring(tree)
        S.smb2_trees[#S.smb2_trees+1] = t
        S.smb2_last_tree[ck] = t
      elseif stv and S.smb2_last_tree[ck] then
        local t = S.smb2_last_tree[ck]
        S.smb2_last_tree[ck] = nil
        if stv == 0xC00000CC then
          inc(S.smb2_badname, t)
        end
      end
    end
  end
  -- NTLMSSP: kullanıcı adları ve NULL oturumlar
  local ntlm_u = V(fi_ntlm_user)
  if ntlm_u then
    local u = tostring(ntlm_u)
    local dom = V(fi_ntlm_dom)
    if u == "NULL" or u == "" or u == "(null)" then
      S.ntlm_null = S.ntlm_null + 1
    else
      local k = (dom and tostring(dom) or "") .. "\\" .. u
      inc(S.ntlm_users, k)
      if stream then S.smb2_last_user[tostring(stream)] = k end
    end
  end
  -- SMB2 dosya envanteri: Create (cmd 5) adı + tcp.stream kaydet; Read(8)/Write(9) baytları stream'e ata
  if scmd == 5 then
    local fn = V(fi_smb2_fname)
    if fn and tostring(fn) ~= "<share>" and stream then
      local f = tostring(fn)
      if not S.smb2_files[f] then S.smb2_files[f] = { reads = 0, writes = 0, src = tostring(src), streams = {} } end
      S.smb2_files[f].streams[tostring(stream)] = true
      if not S.smb2_files[f].user then S.smb2_files[f].user = S.smb2_last_user[tostring(stream)] end
    end
  elseif (scmd == 8 or scmd == 9) and stream then
    local st = tostring(stream)
    local amt = (scmd == 8) and (N(fi_smb2_readlen) or 0) or (N(fi_smb2_writelen) or 0)
    if amt > 0 then
      for fname, fd in pairs(S.smb2_files) do
        if fd.streams and fd.streams[st] then
          if scmd == 8 then fd.reads = (fd.reads or 0) + amt else fd.writes = (fd.writes or 0) + amt end
          break
        end
      end
    end
  end
  -- Kerberos etype: RC4 (23) bilet — Kerberoasting keskin imzası
  -- (kerberos.etype TGS-REP'te çoklu örnek: [istek etypes..., bilet etype])
  if N(fi_krb_msgtype) == 13 then
    local okE, tE = pcall(function() return { fi_krb_etype() } end)
    if okE and tE then
      for _, ex in ipairs(tE) do
        if tonumber(ex.value) == 23 then
          S.krb_etype23 = S.krb_etype23 + 1
          inc(S.krb_etype_srcs, tostring(dst))
          break
        end
      end
    end
  end
  -- ICMP tünel adayı: identifier tekrarı + büyük payload
  local iid = N(fi_icmp_ident)
  if iid and N(fi_icmp_type) == 8 then
    local k = tostring(iid)
    S.icmp_ident_cnt[k] = (S.icmp_ident_cnt[k] or 0) + 1
    if S.icmp_ident_cnt[k] >= 3 then
      S.icmp_tunnel_hits[k] = S.icmp_ident_cnt[k]
    end
  end
  -- Fragment overlap
  if P(fi_frag_overlap) == 1 then S.frag_overlap_n = S.frag_overlap_n + 1 end
  if P(fi_frag_conflict) == 1 then S.frag_conflict_n = S.frag_conflict_n + 1 end
  -- Sertifika zaman damgaları + zayıf imza
  local x5t = V(fi_x509_utctime)
  if x5t then S.x509_times[#S.x509_times+1] = tostring(x5t) end
  local sig = V(fi_tls_sigalg)
  if sig then
    local sg = tostring(sig):lower()
    if sg:find("sha1", 1, true) or sg:find("md5", 1, true) then
      S.tls_weak_sig = S.tls_weak_sig + 1
    end
  end
  -- SAMR (dizin listeleme) — DCERPC over SMB pipe
  -- not: frame.protocols "samr" içermez (heuristic dissector) — ayrı filtreli listener sayar

  -- ── FTP ──
  local fcmd = V(fi_ftp_cmd)
  if fcmd then
    local c = tostring(fcmd)
    if c == "USER" or c == "PASS" then
      local arg = V(fi_ftp_arg)
      S.ftp_logins[#S.ftp_logins+1] = { ts = ts, src = tostring(src), cmd = c, arg = arg and tostring(arg) or "-" }
      S.first_ftp_ts = S.first_ftp_ts or ts
    elseif c == "PORT" then
      local arg = V(fi_ftp_arg)
      if arg then
        local a = tostring(arg)
        local h1,h2,h3,h4,p1,p2 = a:match("^(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
        if h1 then
          local target_ip = h1 .. "." .. h2 .. "." .. h3 .. "." .. h4
          local target_port = tonumber(p1) * 256 + tonumber(p2)
          S.ftp_port_args[#S.ftp_port_args+1] = {
            src = tostring(src), peer = tostring(src), target_ip = target_ip,
            target_port = target_port, bounce = target_ip ~= tostring(src),
          }
        end
      end
    end
  end
  local fcode = N(fi_ftp_code)
  if fcode then
    if fcode == 530 then S.ftp_fails = S.ftp_fails + 1
    elseif fcode == 230 then S.ftp_ok = S.ftp_ok + 1 end
  end

  -- ── Mail ──
  local scmdm = V(fi_smtp_cmd)
  if scmdm then
    local c = tostring(scmdm)
    local prm = V(fi_smtp_param)
    prm = prm and tostring(prm) or ""
    if c == "MAIL" then S.smtp_from[#S.smtp_from+1] = prm
    elseif c == "RCPT" then S.smtp_to[#S.smtp_to+1] = prm
    elseif c == "AUTH" then S.smtp_auth_b64[#S.smtp_auth_b64+1] = { src = tostring(src) } end
  end
  local pu, pp = V(fi_pop_user), V(fi_pop_pass)
  if pu then S.pop_creds[#S.pop_creds+1] = { user = tostring(pu), pass = pp and tostring(pp) or "-" } end
  local imapr = V(fi_imap_req)
  if imapr then
    local r = tostring(imapr)
    inc(S.imap_cmds, r:match("^(%u+)") or r)
    if r:find("LOGIN") then
      local u, p = r:match("LOGIN%s+(%S+)%s+(%S+)")
      if u then S.pop_creds[#S.pop_creds+1] = { user = u, pass = p, proto = "IMAP" } end
    end
  end

  -- ── WLAN ──
  local subtype = N(fi_wlan_subtype)
  if subtype then
    inc(S.wlan_subtypes, subtype)
    if subtype == 12 then S.deauth = S.deauth + 1 end
  end
  local ssid = V(fi_wlan_ssid)
  if ssid and #tostring(ssid) > 0 then inc(S.ssids, tostring(ssid)) end
  local dbm = N(fi_radiotap_dbm)
  if dbm then S.rssi[#S.rssi+1] = dbm end
  local info_col = pinfo.cols and pinfo.cols.info and tostring(pinfo.cols.info) or ""
  if info_col:find("EAPOL") then S.eapol = S.eapol + 1 end

  -- ── SIP/RTP ──
  local sipm = V(fi_sip_method)
  if sipm then inc(S.sip_methods, tostring(sipm)) end
  if N(fi_rtp_ssrc) then
    local k = tostring(src) .. "->" .. tostring(dst)
    if not S.rtp_streams[k] then S.rtp_streams[k] = { pkts = 0 } end
    S.rtp_streams[k].pkts = S.rtp_streams[k].pkts + 1
  end

  -- ── TCP payload taraması (mail ekleri, konular, Basic auth) ──
  local pl = RAW(fi_tcp_payload)
  if pl and #pl > 16 then
    local dport_p = dport or 0
    local lower = pl:lower()
    if lower:find("content-transfer-encoding: base64", 1, true)
       or lower:find("content-disposition: attachment", 1, true) then
      local fn = pl:match('filename="([^"]+)"') or pl:match("filename=([^;\r\n]+)")
      S.mail_attach[#S.mail_attach+1] = {
        src = tostring(src), dst = tostring(dst), dport = dport_p,
        filename = fn or "(ad çözülemedi)",
      }
    end
    local subj = pl:match("Subject:%s*([^\r\n]+)")
    if subj and #S.smtp_subjects < 16 then
      S.smtp_subjects[#S.smtp_subjects+1] = subj
    end
    local b64 = lower:match("authorization:%s*basic%s+([A-Za-z0-9+/=]+)")
    if b64 then
      S.creds[#S.creds+1] = {
        ts = ts,
        src = tostring(src),
        ctx = "HTTP Authorization: Basic (base64)",
        data = (b64:gsub("%s+", "")),
      }
      S.http_basic_auth = (S.http_basic_auth or 0) + 1
    end
  end

  -- ── Expert ──
  if pinfo.cols and pinfo.cols.info and tostring(pinfo.cols.info):find("Expert") then S.experts = S.experts + 1 end
end

-- ═════════════════════════ DAVRANIŞ ANALİZİ ═══════════════════════════
local function beacon_analysis()
  local beacons = {}
  for k, times in pairs(S.conn_times) do
    if #times >= 4 then
      table.sort(times)
      -- paralel patlama (flood/parallel bağlantı) tekilleştirilir
      local merged = { times[1] }
      for i = 2, #times do
        if times[i] - merged[#merged] > 0.4 then merged[#merged+1] = times[i] end
      end
      times = merged
      if #times >= 4 then
        local diffs, sum = {}, 0
        for i = 2, #times do
          local d = times[i] - times[i-1]
          diffs[#diffs+1] = d
          sum = sum + d
        end
        -- sağlam (robust) aralık: medyan temelli; patlama/artık aralıklar ayıklanır
        local sorted_d = {}
        for _, d in ipairs(diffs) do sorted_d[#sorted_d+1] = d end
        table.sort(sorted_d)
        local median = sorted_d[math.ceil(#sorted_d / 2)]
        local kept, ksum = {}, 0
        for _, d in ipairs(diffs) do
          if d >= median * 0.5 and d <= median * 1.5 then
            kept[#kept+1] = d
            ksum = ksum + d
          end
        end
        if #kept >= 3 and #kept / #diffs >= 0.5 then
          local mean = ksum / #kept
          local var = 0
          for _, d in ipairs(kept) do var = var + (d - mean) ^ 2 end
          local stdev = math.sqrt(var / #kept)
          -- düzenli aralık: std/mean düşük VE aralık 1sn-10dk
          if mean >= 0.8 and mean <= 600 and (stdev / math.max(mean, 1e-9)) < 0.35 then
            beacons[#beacons+1] = { key = k, count = #times, mean = mean, jitter = stdev / math.max(mean, 1e-9) }
          end
        end
      end
    end
  end
  table.sort(beacons, function(a,b) return a.count > b.count end)
  return beacons
end

local function port_scan_analysis()
  local scans = {}
  for src, ports in pairs(S.syn_by_src_port) do
    local n = 0
    for _ in pairs(ports) do n = n + 1 end
    if n >= 6 then
      local open_ports, closed = {}, 0
      for p in pairs(ports) do
        local k = src .. "->" .. "?" -- pair-lookup: syn_by_pair içinde var mı
        -- açık/closed tespiti: synack_by_pair'i tara
        scans[#scans+1] = nil -- placeholder (aşağıda dolduruluyor)
        break
      end
      scans[#scans] = nil
      -- yeniden: bu kaynağın SYN'lerinden kaçına SYN-ACK+ACK (tam handshake) geldi?
      local completed = 0
      local targets = {}
      for pairk in pairs(S.syn_by_pair) do
        local s, rest = pairk:match("^(%S+)%-(%S+)$")
        -- pairk formatı: src->dst:port
        local psrc, pdst, pport = pairk:match("^(.-)%->(.-):(%d+)$")
        if psrc == src then
          targets[pdst] = targets[pdst] or {}
          targets[pdst][tonumber(pport)] = S.handshake_done[pairk] or S.syn_nocomplete[pairk] == nil
        end
      end
      local halfopen, connect_open = 0, 0
      for pairk, _ in pairs(S.syn_by_pair) do
        local psrc = pairk:match("^(.-)%->")
        if psrc == src then
          if S.handshake_done[pairk] then connect_open = connect_open + 1
          else halfopen = halfopen + 1 end
        end
      end
      scans[#scans+1] = { src = src, uniq_ports = n, halfopen = halfopen, connect_open = connect_open }
    end
  end
  table.sort(scans, function(a,b) return a.uniq_ports > b.uniq_ports end)
  return scans
end

local function syn_flood_analysis()
  -- tek kaynağın, tamamlanmayan SYN'lerinin oranı
  local out = {}
  for pairk in pairs(S.syn_nocomplete) do
    local psrc = pairk:match("^(.-)%->")
    out[psrc] = (out[psrc] or 0) + 1
  end
  local floods = {}
  for src, n in pairs(out) do
    if n >= 15 then floods[#floods+1] = { src = src, unanswered = n } end
  end
  table.sort(floods, function(a,b) return a.unanswered > b.unanswered end)
  return floods
end

local function arp_sweep_analysis()
  local out = {}
  for k, cnt in pairs(S.arp_req_pairs) do
    local mac, tip = k:match("^(.-)%->(.+)$")
    -- tek MAC, çok sayıda TEKİL hedef (yanıtsız hedeflerde 1-3 tekrar normal)
    if cnt <= 3 and mac then
      out[mac] = (out[mac] or 0) + 1
    end
  end
  local sweeps = {}
  for mac, uniq in pairs(out) do
    if uniq >= 6 then sweeps[#sweeps+1] = { mac = mac, targets = uniq } end
  end
  table.sort(sweeps, function(a,b) return a.targets > b.targets end)
  return sweeps
end

-- ═════════════════════════ RAPOR ══════════════════════════════════════
local function esc(s) s = tostring(s or "") return s:gsub("%|", "/") end

local function fmt_top(tbl, header, n, min)
  local rows = topN(tbl, n or 8, min)
  if #rows == 0 then return nil end
  local out = "| " .. table.concat(header, " | ") .. " |\n"
  out = out .. "|" .. string.rep("---|", #header) .. "\n"
  for _, r in ipairs(rows) do
    out = out .. "| " .. esc(r[1]) .. " | " .. tostring(r[2]) .. " |\n"
  end
  return out
end

local function build_report(pcap_path)
  local L = {}
  local function w(s) L[#L+1] = s end
  local dur = (S.first_ts and S.last_ts) and (S.last_ts - S.first_ts) or 0
  local base = pcap_path and pcap_path:match("([^/\\]+)$") or "capture"

  w("# Shark-Tank Bulgu Raporu — " .. base)
  w("")
  w("- **Araç:** shark-tank.lua v" .. ST.version .. " — desen tabanlı ağ analizi")
  w("- **Paket sayısı:** " .. S.pkts)
  w("- **Zaman aralığı:** " .. ts_str(S.first_ts or 0) .. " sn → " .. ts_str(S.last_ts or 0) .. " sn (süre " .. string.format("%.2f", dur) .. " sn)")
  w("- **Protokol hiyerarşisi (ilk 12):**")
  local ph = topN(S.protos, 12)
  for _, r in ipairs(ph) do w("  - `" .. r[1] .. "`: " .. r[2] .. " paket") end
  w("")

  -- ── 1. Keşif ──────────────────────────────────────────────────────
  w("## 1. Keşif (Reconnaissance)")
  w("")
  local sweeps = arp_sweep_analysis()
  if #sweeps > 0 then
    w("### ARP Host Keşfi (sweep)")
    for _, s in ipairs(sweeps) do
      w("- MAC `" .. s.mac .. "` çok sayıda TEKİL hedefe ARP request gönderdi: **" .. s.targets .. " benzersiz IP** → keşif taraması imzası")
    end
    w("- **Filtre:** `arp.opcode == 1 && arp.src.hw_mac == \"" .. sweeps[1].mac .. "\"`")
    w("")
  end
  local scans = port_scan_analysis()
  if #scans > 0 then
    w("### Port Taraması")
    for _, s in ipairs(scans) do
      local tip = (s.halfopen >= s.connect_open) and "**half-open (SYN scan)**" or "**connect scan** ağırlıklı"
      w("- Kaynak `" .. s.src .. "`: **" .. s.uniq_ports .. " benzersiz porta SYN**; tamamlanan el sıkışma: " .. s.connect_open .. ", yarım kalan: " .. s.halfopen .. " → " .. tip)
    end
    w("- **Filtre:** `ip.addr == " .. scans[1].src .. " && tcp.flags.syn == 1 && tcp.flags.ack == 0`")
    w("")
  end
  local floods = syn_flood_analysis()
  if #floods > 0 then
    w("### SYN Flood Adayı")
    for _, f in ipairs(floods) do
      w("- `" .. f.src .. "`: " .. f.unanswered .. " yanıtlanmayan SYN → DoS/flood göstergesi")
    end
    w("- **Filtre:** `ip.src == " .. floods[1].src .. " && tcp.flags.syn == 1 && !tcp.analysis.acks_frame`")
    w("")
  end
  if S.arp_dup > 0 then
    w("### ARP Çakışması / Spoofing")
    w("- **" .. S.arp_dup .. " kez** bir IP adresi için birden fazla MAC görüldü → ARP poisoning adayı")
    w("- **Filtre:** `arp.duplicate-address-detected || arp.duplicate-frame-detected`")
    w("")
  end
  if S.icmp_redirect_gw > 0 then
    w("### ICMP Redirect Denemesi")
    w("- " .. S.icmp_redirect_gw .. " adet Redirect (tip 5) paketi: trafiğin başka ağ geçidine çekilme girişimi (IP-MAC eşleşmesini doğrulayın)")
    w("- **Filtre:** `icmp.type == 5`")
    w("")
  end
  local ra = topN(S.ra_srcs, 3, 2)
  if #ra > 1 then
    w("### IPv6 Rogue RA Şüphesi")
    w("- Birden fazla kaynak Router Advertisement gönderiyor:")
    for _, r in ipairs(ra) do w("  - `" .. r[1] .. "`: " .. r[2] .. " RA") end
    w("- **Filtre:** `icmpv6.type == 134`")
    w("")
  end
  if (#sweeps + #scans + #floods) == 0 and S.arp_dup == 0 then
    w("- Keşif göstergesi bulunamadı.")
    w("")
  end

  -- ── 2. Kimlik bilgileri ───────────────────────────────────────────
  w("## 2. Kimlik Bilgisi Sızıntısı (Initial Access)")
  w("")
  local cred_found = false
  if #S.creds > 0 then
    cred_found = true
    w("### HTTP POST içinde açık metin kimlik bilgisi")
    for _, c in ipairs(S.creds) do
      w("- `" .. c.src .. "` → " .. esc(c.ctx) .. ": `" .. esc(c.data) .. "`")
    end
    w("")
  end
  if #S.ftp_logins > 0 then
    cred_found = true
    w("### FTP cleartext oturum bilgisi")
    local seen = {}
    for _, l in ipairs(S.ftp_logins) do
      local k = l.src .. l.cmd .. l.arg
      if not seen[k] then
        seen[k] = true
        w("- `" .. l.src .. "` — " .. l.cmd .. ": `" .. esc(l.arg) .. "`")
      end
    end
    if S.ftp_fails > 0 then
      w("- **" .. S.ftp_fails .. " başarısız (530)**, " .. S.ftp_ok .. " başarılı (230) deneme" .. (S.ftp_fails >= 5 and " → brute force imzası" or ""))
    end
    w("- **Filtre:** `ftp.request.command == \"PASS\" || ftp.response.code == 530`")
    w("")
  end
  if #S.pop_creds > 0 then
    cred_found = true
    w("### POP3/IMAP cleartext giriş")
    for _, c in ipairs(S.pop_creds) do
      w("- kullanıcı: `" .. esc(c.user) .. "` şifre: `" .. esc(c.pass) .. "`")
    end
    w("")
  end
  if #S.ldap_simple > 0 then
    cred_found = true
    w("### LDAP simple bind (parola ağda)")
    local seen = {}
    for _, b in ipairs(S.ldap_simple) do
      local k = b.src .. b.name
      if not seen[k] then
        seen[k] = true
        w("- `" .. b.src .. "` — kullanıcı: `" .. esc(b.name) .. "` parola: `" .. esc(b.pass) .. "`")
      end
    end
    if S.ldap_result49 > 0 then w("- " .. S.ldap_result49 .. " kez invalidCredentials (49) → parola denemesi") end
    w("")
  end
  if not cred_found then w("- Açık metin kimlik bilgisi bulunamadı.") w("") end

  -- ── 3. Sömürü girişimleri ─────────────────────────────────────────
  w("## 3. Sömürü Girişimleri (Delivery/Exploitation)")
  w("")
  local expl = false
  if S.sqli + S.xss + S.traversal > 0 then
    expl = true
    w("- **SQL injection kalıbı:** " .. S.sqli .. " istek (`UNION SELECT`, `OR 1=1`, `sleep()`...)")
    w("- **XSS kalıbı:** " .. S.xss .. " istek (`<script>`, `onerror=`, `document.cookie`...)")
    w("- **Path traversal kalıbı:** " .. S.traversal .. " istek (`../`, `/etc/passwd`...)")
    w("- **Filtre:** `http.request.uri contains \"UNION\" || http.request.uri contains \"<script>\"`")
    w("")
  end
  if #S.krb_errors > 0 then
    expl = true
    w("### Kerberos hata/kırma izleri")
    local ecnt = {}
    for _, e in ipairs(S.krb_errors) do inc(ecnt, e) end
    local KRB_ERR = {
      ["6"] = "KDC_ERR_S_NAME_PRINCIPAL_UNKNOWN (bilinmeyen servis)",
      ["24"] = "KDC_ERR_PREAUTH_FAILED (yanlış parola!)",
      ["25"] = "KDC_ERR_PREAUTH_REQUIRED (normal ön kimlik)",
      ["37"] = "KRB_AP_ERR_SKEW (saat kayması)",
    }
    for k, v in pairs(ecnt) do
      w("- error_code " .. k .. ": " .. v .. " kez" .. (KRB_ERR[k] and " — " .. KRB_ERR[k] or ""))
    end
    -- kaynak başına kullanıcı denemeleri: sprey (çok farklı kullanıcı) / tek hedef brute
    for src, tbl in pairs(S.krb_cnames_by_src) do
      local total, distinct, maxone = 0, 0, 0
      for _, c in pairs(tbl) do total = total + c; distinct = distinct + 1; if c > maxone then maxone = c end end
      if distinct >= 4 then
        w("- `" .. src .. "` → **" .. distinct .. " farklı kullanıcı** için toplam " .. total .. " istek → **parola spreyi** imzası")
      elseif maxone >= 5 then
        w("- `" .. src .. "` → tek kullanıcı için " .. maxone .. " deneme → parola tahmini (brute) şüphesi")
      end
    end
    local distinct_spn = 0
    for _ in pairs(S.krb_snames) do distinct_spn = distinct_spn + 1 end
    if distinct_spn >= 3 and S.krb_tgsreq >= 3 then
      w("- Tek kaynak, " .. distinct_spn .. " farklı servis bileti (TGS-REQ) → **Kerberoasting** imzası")
    end
    if S.krb_etype23 > 0 then
      local rc4src = topN(S.krb_etype_srcs, 3, 1)
      for _, r in ipairs(rc4src) do
        w("- **" .. S.krb_etype23 .. " bilet RC4 (etype 23) ile şifrelendi** — alıcı `" .. r[1] .. "` → kırılabilir bilet toplandı (Kerberoasting kesin imzası)")
      end
      w("- **Filtre:** `kerberos.etype == 23`")
    end
    w("")
  end
  -- ICMP tüneli
  local tun = topN(S.icmp_tunnel_hits, 3, 3)
  if #tun > 0 then
    expl = true
    w("### ICMP Tüneli Şüphesi (sabit identifier)")
    for _, r in ipairs(tun) do
      w("- Identifier **" .. r[1] .. " (0x" .. string.format("%x", tonumber(r[1]) or 0) .. ")** ile " .. r[2] .. " Echo Request → tek oturum, sabit kimlik (gerçek ping rastgele üretir)")
    end
    w("- **Filtre:** `icmp.ident == 0x" .. string.format("%x", tonumber(tun[1][1]) or 0) .. "` — payload'da base64/heks veri aranmalı")
    w("")
  end
  -- Fragment overlap
  if S.frag_overlap_n > 0 then
    expl = true
    w("### IP Fragment Overlap (teardrop/evasion)")
    w("- **" .. S.frag_overlap_n .. " çakışan reassembly**" .. (S.frag_conflict_n > 0 and (", " .. S.frag_conflict_n .. " tanesinde veri ÇAKIŞIYOR (conflict)") or ""))
    w("- **Filtre:** `ip.fragment.overlap || ip.fragment.overlap.conflict` → IDS bypass şüphesi")
    w("")
  end
  local smb_fails = topN(S.smb2_fail_by_src, 3, 3)
  if #smb_fails > 0 then
    expl = true
    w("### SMB brute force")
    for _, r in ipairs(smb_fails) do
      w("- `" .. r[1] .. "`: " .. r[2] .. " kez STATUS_LOGON_FAILURE (0xc000006d)")
    end
    w("- **Filtre:** `smb2.nt_status == 0xc000006d`")
    w("")
  end
  -- Harici SMB share denemeleri (STATUS_BAD_NETWORK_NAME fırtınası)
  local badnames = topN(S.smb2_badname, 4, 2)
  if #badnames > 0 then
    expl = true
    w("### Harici SMB Share Denemesi (lateral movement / yayılma)")
    for _, r in ipairs(badnames) do
      w("- Tree `" .. esc(r[1]) .. "`: **" .. r[2] .. " kez STATUS_BAD_NETWORK_NAME** → var olmayan paylaşıma ısrarlı erişim")
    end
    w("- **Filtre:** `smb2.cmd == 3 && smb2.nt_status == 0xc00000cc`")
    w("")
  end
  -- NTLM NULL oturum
  if S.ntlm_null > 0 then
    expl = true
    w("### Anonim (NULL) SMB Oturumu")
    w("- **" .. S.ntlm_null .. " kez NULL/anonymous NTLMSSP kimlik doğrulaması** → dizin/paylaşım keşfi imzası")
    w("- **Filtre:** `ntlmssp.auth.username == \"NULL\"`")
    w("")
  end
  -- SAMR dizin listeleme
  local samr_src = topN(S.samr_srcs, 3, 4)
  if #samr_src > 0 then
    expl = true
    w("### SAMR ile Dizin Listeleme (DCERPC over SMB)")
    for _, r in ipairs(samr_src) do
      w("- `" .. r[1] .. "`: " .. r[2] .. " SAMR çağrısı (OpenDomain/OpenUser/QueryUserInfo → kullanıcı/grup envanteri)")
    end
    w("- **Filtre:** `samr` — samr pipe'ı üzerinden AD nesne keşfi (BloodHound benzeri araç imzası)")
    w("")
  end
  if #S.ftp_port_args > 0 then
    local bounced = {}
    for _, p in ipairs(S.ftp_port_args) do
      if p.bounce then bounced[#bounced+1] = p end
    end
    if #bounced > 0 then
      expl = true
      w("### FTP Bounce Denemesi")
      for _, p in ipairs(bounced) do
        w("- PORT hedefi `" .. p.target_ip .. ":" .. p.target_port .. "` ≠ kontrol bağlantısı kaynağı `" .. p.src .. "` → üçüncü tarafa atlama")
      end
      w("- **Filtre:** `ftp.request.command == \"PORT\"`")
      w("")
    end
  end
  if not expl then w("- Web/dizin servis sömürüsü kalıbı bulunamadı.") w("") end

  -- ── 4. Komuta kontrol ─────────────────────────────────────────────
  w("## 4. Komuta Kontrol (C2 / Beaconing)")
  w("")
  local beacons = beacon_analysis()
  if #beacons > 0 then
    for i = 1, math.min(#beacons, 5) do
      local b = beacons[i]
      local bsrc, bdst, bport = b.key:match("^(.-)%|(.-)%|(.+)$")
      local hint = ""
      local known = { ["21"]="FTP kontrol (brute force da olabilir)", ["22"]="SSH (otomatik görev de olabilir)",
                      ["25"]="SMTP (mail botu da olabilir)", ["389"]="LDAP (dizin aracı olabilir)",
                      ["445"]="SMB (paylaşım taraması olabilir)", ["636"]="LDAPS" }
      if known[tostring(bport)] then hint = " — hedef " .. bport .. ": " .. known[tostring(bport)] end
      w("- `" .. b.key .. "`: " .. b.count .. " bağlantı, ortalama aralık **" .. string.format("%.2f", b.mean) .. " sn**, jitter oranı " .. string.format("%.0f%%", b.jitter * 100) .. " → düzenli heartbeat (C2 adayı)" .. hint)
    end
    local src, dst, port = beacons[1].key:match("^(.-)%|(.-)%|(.+)$")
    w("- **Filtre:** `ip.addr == " .. esc(src) .. " && ip.addr == " .. esc(dst) .. " && tcp.dstport == " .. esc(port) .. "`")
    w("")
  else
    w("- Düzenli aralıklı bağlantı deseni bulunamadı.")
    w("")
  end

  -- ── 5. Veri sızıntısı ─────────────────────────────────────────────
  w("## 5. Veri Sızıntısı (Exfiltration) & Entropi")
  w("")
  local exf = false
  if #S.dns_long_labels > 0 then
    exf = true
    w("### DNS tüneli şüphesi")
    for i = 1, math.min(#S.dns_long_labels, 5) do
      local q = S.dns_long_labels[i]
      local e = S.dns_entropies[i]
      w("- Uzun etiketli sorgu: `" .. q .. "` (Shannon entropisi " .. string.format("%.2f", e.H) .. " bit/karakter)")
    end
    w("- **Filtre:** `dns.qry.name.len > 40`")
    w("")
  end
  local hi_post
  for _, p in ipairs(S.http_big_posts) do
    if p.H and p.H >= 5.0 and p.len >= 256 then hi_post = hi_post or {} ; hi_post[#hi_post+1] = p end
  end
  if hi_post then
    exf = true
    w("### Yüksek entropili büyük POST gövdesi")
    for _, p in ipairs(hi_post) do
      w("- `" .. p.src .. "` → " .. esc(p.uri) .. ": " .. p.len .. " bayt, entropi **" .. string.format("%.3f", p.H) .. " bit/karakter**" .. (p.looks_b64 and " (base64 deseni)" or "") .. " → şifreli/sıkıştırılmış veri sızdırma adayı")
    end
    w("- **Filtre:** `http.request.method == \"POST\" && http.content_length > 256`")
    w("")
  end
  local asym = {}
  for _, c in pairs(S.conv) do
    local tot = c.a2b + c.b2a
    if tot > 50000 then
      local ratio = (math.min(c.a2b, c.b2a) + 1) / (math.max(c.a2b, c.b2a) + 1)
      if ratio < 0.05 then
        asym[#asym+1] = { pair = c.a .. " ↔ " .. c.b, big = math.max(c.a2b, c.b2a), small = math.min(c.a2b, c.b2a) }
      end
    end
  end
  if #asym > 0 then
    exf = true
    w("### Tek yönlü büyük aktarım (asimetri)")
    for i = 1, math.min(#asym, 5) do
      local a = asym[i]
      w("- " .. a.pair .. ": " .. a.big .. " bayt ↔ " .. a.small .. " bayt (oran < %5) → toplu indirme/yükleme")
    end
    w("")
  end
  if #S.downloads > 0 then
    exf = true
    w("### İndirilen/aktarılan dosyalar")
    for _, d in ipairs(S.downloads) do
      w("- " .. ts_str(d.ts) .. " sn — `" .. d.src .. "` → `" .. d.dst .. "` : " .. esc(d.uri))
    end
    w("- **Kurtarma:** `tshark -r <pcap> --export-objects http,<dizin>`; magic bytes ile gerçek tip doğrulanır (PK=ZIP, MZ=EXE, %PDF=PDF)")
    w("")
  end
  if not exf then w("- Sızıntı göstergesi bulunamadı.") w("") end

  -- ── 6. Protokol derinlemesine ─────────────────────────────────────
  w("## 6. Protokol Detayları")
  w("")
  -- DNS
  local nq = 0; for _ in pairs(S.dns_q) do nq = nq + 1 end
  if nq > 0 then
    w("### DNS")
    w("- " .. nq .. " benzersiz sorgu; NXDOMAIN: " .. (function() local n=0 for _ in pairs(S.dns_nxdomain) do n=n+1 end return n end)() .. "; TXT sorgusu: " .. S.dns_txt_cnt)
    local nx = topN(S.dns_nxdomain, 5, 2)
    for _, r in ipairs(nx) do w("  - NXDOMAIN `" .. r[1] .. "`: " .. r[2] .. " kez") end
    w("")
  end
  -- HTTP
  if #S.http_reqs > 0 then
    w("### HTTP")
    local t = fmt_top(S.http_codes, {"Status", "Adet"}, 6)
    if t then w("- Yanıt kodları:\n\n" .. t) end
    local t2 = fmt_top(S.uas, {"User-Agent", "Adet"}, 6)
    if t2 then w("- İstemciler:\n\n" .. t2) end
    if S.fake_uas and #S.fake_uas > 0 then
      w("- **Sahte User-Agent şüphesi** (eski IE + modern Windows — gerçek tarayıcıda imkânsız bileşim, malware UA'sı):")
      local seenUA = {}
      for _, f in ipairs(S.fake_uas) do
        if not seenUA[f.ua] then
          seenUA[f.ua] = true
          w("  - `" .. esc(f.src) .. "` → `" .. esc(f.ua) .. "`")
        end
      end
    end
    if S.chunked > 0 then w("- " .. S.chunked .. " chunked yanıt (Content-Length yok; gövde chunk başına yeniden birleştirilmeli)") end
    -- Basic auth: çözülmüş kimlik bilgisi
    local basicauth = {}
    for _, c in ipairs(S.creds) do
      if c.ctx:find("Basic", 1, true) then
        local dec = b64decode(c.data)
        if #dec > 0 then basicauth[#basicauth+1] = { src = c.src, cred = dec:sub(1, 80) } end
      end
    end
    if #basicauth > 0 then
      w("- **HTTP Basic auth (base64 çözülmüş):**")
      local seenB = {}
      for _, b in ipairs(basicauth) do
        if not seenB[b.cred] then
          seenB[b.cred] = true
          w("  - `" .. b.src .. "` → `" .. esc(b.cred) .. "` (filtre: `http.authbasic`)")
        end
      end
    end
    w("")
  end
  -- Cookie
  if #S.cookies > 0 then
    w("### Oturum token'ları (Set-Cookie → Cookie)")
    for i = 1, math.min(#S.cookies, 6) do
      local c = S.cookies[i]
      w("- [" .. c.dir .. "] `" .. esc(c.val) .. "`")
    end
    w("- **Filtre:** `http.cookie || http.set_cookie`")
    w("")
  end
  -- DNS→GET delta
  if #S.dns_get_delta > 0 then
    w("### DNS→HTTP zaman deltası")
    for _, d in ipairs(S.dns_get_delta) do
      w("- `" .. d.host .. "`: DNS yanıtı ile ilk GET arası **" .. string.format("%.3f", d.delta) .. " sn**")
    end
    w("")
  end
  -- TLS
  if S.tls_ch > 0 then
    w("### TLS")
    local tv = fmt_top(S.tls_versions, {"Sürüm", "Kayıt"}, 6)
    if tv then w("- Sürümler:\n\n" .. tv) end
    local tc = fmt_top(S.tls_ciphers, {"Cipher", "Seçim"}, 5)
    if tc then w("- Seçilen cipher'lar:\n\n" .. tc) end
    local ts_ = fmt_top(S.tls_snis, {"SNI (hedef alan adı)", "Adet"}, 8)
    if ts_ then w("- SNI'ler (şifreli trafiğin görünen yüzü):\n\n" .. ts_) end
    if #S.tls_ocsp > 0 then
      w("- OCSP: " .. #S.tls_ocsp .. " durum mesajı")
      local st = {}
      for _, v in ipairs(S.tls_ocsp) do inc(st, v) end
      for k, v in pairs(st) do
        local label = (k == "0") and "good (geçerli)" or (k == "1") and "revoked (İPTAL!)" or "unknown"
        w("  - " .. label .. ": " .. v)
      end
    end
    -- Sertifika sağlığı
    if S.tls_weak_sig > 0 then
      w("- **Zayıf imza algoritması (SHA-1/MD5): " .. S.tls_weak_sig .. " el sıkışma** → sahtelenebilir sertifika")
    end
    if #S.x509_times > 0 then
      w("- Sertifika geçerlilik örnekleri (notBefore/notAfter çiftleri, ilk 3): " .. table.concat(S.x509_times, " / ", 1, math.min(#S.x509_times, 6)))
      w("- Kontrol listesi: issuer zinciri → tarih aralığı (notAfter ≥ capture zamanı) → imza algoritması → CN/SNI eşleşmesi")
    end
    w("")
  end
  -- Kerberos
  if S.krb_asreq + S.krb_tgsreq > 0 then
    w("### Kerberos")
    w("- AS-REQ: " .. S.krb_asreq .. ", AS-REP: " .. S.krb_asrep .. ", TGS-REQ: " .. S.krb_tgsreq)
    local tsn = fmt_top(S.krb_snames, {"SPN (servis)", "TGS-REQ"}, 6)
    if tsn then w("- İstenen servis biletleri:\n\n" .. tsn) end
    w("")
  end
  -- LDAP
  if #S.ldap_simple + S.ldap_anon + S.ldap_gssapi > 0 then
    w("### LDAP")
    w("- simple bind: " .. #S.ldap_simple .. ", anonim: " .. S.ldap_anon .. ", GSSAPI: " .. S.ldap_gssapi)
    if #S.ldap_limits > 0 then
      w("- Sunucu limiti kullanan sorgular:")
      for i = 1, math.min(#S.ldap_limits, 5) do
        local l = S.ldap_limits[i]
        w("  - timeLimit=" .. (l.timeLimit or "-") .. ", sizeLimit=" .. (l.sizeLimit or "-"))
      end
    end
    local wide = 0
    for _, f in ipairs(S.ldap_filters) do if f:find("%(objectClass=%*%)") then wide = wide + 1 end end
    if wide > 0 then w("- **" .. wide .. " geniş kapsamlı filtre** `(objectClass=*)` → dizin dökümü (dump) şüphesi") end
    w("")
  end
  -- SMB2
  local nsmb = 0
  for _, v in pairs(S.smb2_cmds) do nsmb = nsmb + v end
  if nsmb > 0 or #S.smb2_trees > 0 then
    w("### SMB2")
    w("- Toplam " .. nsmb .. " SMB2 komutu")
    local seen = {}
    w("- Bağlanılan paylaşımlar:")
    for _, p in ipairs(S.smb2_trees) do
      if not seen[p] then
        seen[p] = true
        local note = (p:find("\\pipe\\") or p:find("IPC")) and " (named pipe — RPC kanalı; samr/svcctl geçerse dizin keşfi/uzaktan servis şüphesi)" or ""
        w("  - `" .. esc(p) .. "`" .. note)
      end
    end
    local ntlm_t = fmt_top(S.ntlm_users, {"NTLM hesabı (alan\\kullanıcı)", "Oturum"}, 6)
    if ntlm_t then w("- Kimlik doğrulayan hesaplar:\n\n" .. ntlm_t) end
    if S.ntlm_null > 0 then w("- **" .. S.ntlm_null .. " anonim (NULL) oturum**") end
    -- Dosya envanteri (Create adları + okunan/yazılan bayt)
    local fnames = {}
    for fn, fd in pairs(S.smb2_files) do fnames[#fnames+1] = { fn, fd } end
    table.sort(fnames, function(a,b) return (a[2].reads + a[2].writes) > (b[2].reads + b[2].writes) end)
    if #fnames > 0 then
      w("")
      w("- Dosya erişim envanteri (Read/Write toplamı):")
      w("")
      w("| Dosya | Okunan (B) | Yazılan (B) | Kaynak |")
      w("|---|---|---|---|")
      for i = 1, math.min(#fnames, 10) do
        local fd = fnames[i][2]
        w("| `" .. esc(fnames[i][1]) .. "` | " .. (fd.reads or 0) .. " | " .. (fd.writes or 0) .. " | `" .. esc(fd.src) .. (fd.user and (" (" .. fd.user .. ")") or "") .. "` |")
      end
      w("")
      w("- Büyük **yazılan** = paylaşım dışına veri çıkışı; büyük **okunan** = dosya toplama (collection) adımı")
    end
    -- svcctl (PsExec ayak izi)
    local svs = topN(S.svcctl_srcs, 3, 2)
    if #svs > 0 then
      for _, r in ipairs(svs) do
        w("- **svcctl** çağrıları: `" .. r[1] .. "` (" .. r[2] .. " paket) → uzaktan servis kontrolü; CreateService/StartService opnum'ları görülürse PsExec/RCE imzası")
      end
      w("- **Filtre:** `svcctl`")
    end
    w("")
  end
  -- Mail
  if #S.smtp_from + #S.pop_creds + #S.mail_attach + #S.smtp_subjects > 0 then
    w("### Email (SMTP/POP3/IMAP)")
    for i = 1, math.min(#S.smtp_from, 5) do w("- " .. esc(S.smtp_from[i])) end
    for i = 1, math.min(#S.smtp_to, 5) do w("- " .. esc(S.smtp_to[i])) end
    for i = 1, math.min(#S.smtp_subjects, 5) do w("- Konu: **" .. esc(S.smtp_subjects[i]) .. "**") end
    if #S.smtp_from > 0 and #S.smtp_to > 0 then
      local fromd = S.smtp_from[1]:match("<(.-)@")
      local tod = S.smtp_to[1]:match("<(.-)@")
      if fromd and tod and fromd ~= tod then
        w("- **Gönderen/alıcı alan adları farklı** → relay/çoğaltma (relaying) değerlendirilmeli")
      end
    end
    if #S.mail_attach > 0 then
      w("- **Ek (attachment) tespit edildi** — kurtarma: Follow TCP Stream + `base64 -d` veya Export Objects > IMF:")
      local seen = {}
      for _, a in ipairs(S.mail_attach) do
        if not seen[a.filename] then
          seen[a.filename] = true
          w("  - `" .. esc(a.filename) .. "` (" .. a.src .. " → " .. a.dst .. ":" .. a.dport .. ")")
        end
      end
    end
    w("")
  end
  -- WLAN
  local nwl = 0
  for _, v in pairs(S.wlan_subtypes) do nwl = nwl + v end
  if nwl > 0 then
    w("### WLAN (802.11)")
    local t = fmt_top(S.ssids, {"SSID", "Paket"}, 6)
    if t then w("- Ağlar:\n\n" .. t) end
    if S.deauth > 0 then w("- **" .. S.deauth .. " deauthentication çerçevesi** → oturum koparma/evil-twin saldırısı imzası (`wlan.fc.type_subtype == 12`)") end
    if S.eapol > 0 then w("- " .. S.eapol .. " EAPOL paketi (WPA el sıkışması)") end
    if #S.rssi >= 5 then
      local mn, mx, sum = 999, -999, 0
      for _, d in ipairs(S.rssi) do if d < mn then mn = d end; if d > mx then mx = d end; sum = sum + d end
      w("- RSSI ortalaması " .. string.format("%.0f dBm", sum / #S.rssi) .. " (aralık " .. mn .. "…" .. mx .. ") — radiotap başlığından")
    end
    w("")
  end
  -- VoIP
  if #S.rtp_streams > 0 or next(S.sip_methods) then
    w("### VoIP (SIP/RTP)")
    local t = fmt_top(S.sip_methods, {"SIP metodu", "Adet"}, 6)
    if t then w(t) end
    for k, v in pairs(S.rtp_streams) do
      w("- RTP akışı " .. k .. ": " .. v.pkts .. " paket")
    end
    w("")
  end

  -- ── 7. Taşıma katmanı sağlık ──────────────────────────────────────
  w("## 7. Taşıma Katmanı Sağlığı")
  w("")
  w("- Retransmission: " .. S.retrans .. " · Duplicate ACK: " .. S.dupack .. " · Zero window: " .. S.zerowin .. " · Out-of-order: " .. S.ooo)
  local rsts = topN(S.rst_by_src, 3, 5)
  for _, r in ipairs(rsts) do
    w("- `" .. r[1] .. "`: " .. r[2] .. " RST gönderdi (" .. (r[2] > 20 and "tarama/kapalı port yanıtı fırtınası" or "bağlantı kesintileri") .. ")")
  end
  w("")

  -- ── 7b. Zaman Çizelgesi ────────────────────────────────────────────
  -- ilk beacon zamanı: en güçlü beacon kanalının ilk bağlantısı
  local first_beacon_ts
  if beacons and beacons[1] then
    local bsrc, bdst, bport = beacons[1].key:match("^(.-)%|(.-)%|(.+)$")
    local bt = S.conn_times[beacons[1].key]
    if bt and bt[1] then first_beacon_ts = bt[1] end
  end
  local events = {}
  if #sweeps > 0 then events[#events+1] = { label = "ARP keşif taraması (" .. sweeps[1].targets .. " hedef)", ts = S.first_arp_ts or S.first_ts or 0 } end
  if #scans > 0 then events[#events+1] = { label = "Port taraması (" .. scans[1].uniq_ports .. " port)", ts = S.first_syn_ts or S.first_ts or 0 } end
  if #S.creds > 0 then events[#events+1] = { label = "Kimlik bilgisi sızdı (cleartext)", ts = S.creds[1].ts or 0 } end
  if #S.ftp_logins > 0 then events[#events+1] = { label = "FTP oturum bilgisi görüldü", ts = S.first_ftp_ts or 0 } end
  if S.sqli + S.xss > 0 then events[#events+1] = { label = "Web sömürü denemesi (SQLi/XSS)", ts = S.first_inject_ts or 0 } end
  if #S.downloads > 0 then events[#events+1] = { label = "Dosya indirildi: " .. esc(S.downloads[1].uri), ts = S.downloads[1].ts } end
  if #beacons > 0 then events[#events+1] = { label = "İlk düzenli beacon", ts = S.first_beacon_ts or 0 } end
  if #S.dns_long_labels > 0 then events[#events+1] = { label = "DNS tüneli sorgusu", ts = S.first_dns_tunnel_ts or 0 } end
  if hi_post and hi_post[1] then events[#events+1] = { label = "Yüksek entropili POST (" .. hi_post[1].len .. " B, H=" .. string.format("%.2f", hi_post[1].H or 0) .. ")", ts = hi_post[1].ts } end
  if #events >= 2 then
    table.sort(events, function(a,b) return a.ts < b.ts end)
    w("## 8. Zaman Çizelgesi (Timeline)")
    w("")
    w("| T (sn) | Olay |")
    w("|---|---|")
    for _, e in ipairs(events) do
      w("| " .. string.format("%.3f", e.ts) .. " | " .. e.label .. " |")
    end
    w("")
  end

  -- ── 8/9. Kill chain ─────────────────────────────────────────────────
  w("## 9. Kill Chain Bütünlemesi")
  w("")
  w("| Aşama | Kanıt | Kaynak(lar) |")
  w("|---|---|---|")
  local kc = false
  if #sweeps > 0 then kc = true; w("| Reconnaissance | ARP sweep (" .. sweeps[1].targets .. " hedef) | `" .. sweeps[1].mac .. "` |") end
  if #scans > 0 then kc = true; w("| Reconnaissance | Port taraması (" .. scans[1].uniq_ports .. " port) | `" .. scans[1].src .. "` |") end
  if cred_found or expl then kc = true; w("| Initial Access | Kimlik bilgisi/sömürü denemesi | bkz. bölüm 2-3 |") end
  if #beacons > 0 then kc = true; w("| Command & Control | Düzenli beacon (" .. string.format("%.1f", beacons[1].mean) .. " sn aralık) | `" .. esc(beacons[1].key) .. "` |") end
  if exf then kc = true; w("| Exfiltration | Yüksek entropili/uzun etiketli/asimetrik aktarım | bkz. bölüm 5 |") end
  if not kc then w("| — | Zincir kanıtı bulunamadı | — |") end
  w("")

  -- ── 9. IOC ────────────────────────────────────────────────────────
  w("## 10. IOC Özeti")
  w("")
  w("```text")
  local ioc = false
  for _, s in ipairs(scans) do ioc = true; w("tarama_kaynağı      : " .. s.src) end
  for _, b in ipairs(beacons) do ioc = true; w("c2_kanalı          : " .. b.key) end
  for i = 1, math.min(#S.dns_long_labels, 3) do ioc = true; w("dns_tüneli_sorgusu : " .. S.dns_long_labels[i]) end
  for _, c in ipairs(S.creds) do ioc = true; w("sızan_kimlik       : " .. esc(c.data)) end
  for _, l in ipairs(S.ldap_simple) do ioc = true; w("ldap_kimlik        : " .. esc(l.name) .. " / " .. esc(l.pass)) break end
  local badn = topN(S.smb2_badname, 3, 2)
  for _, r in ipairs(badn) do ioc = true; w("harici_smb_hedefi  : " .. esc(r[1]) .. " (" .. r[2] .. " deneme)") end
  for k in pairs(S.ntlm_users) do ioc = true; w("ntlm_hesabı        : " .. k) end
  if S.ntlm_null > 0 then ioc = true; w("anonim_smb_oturumu : " .. S.ntlm_null .. " kez") end
  if S.fake_uas and #S.fake_uas > 0 then ioc = true; w("sahte_user_agent   : " .. S.fake_uas[1].ua) end
  if S.krb_etype23 > 0 then ioc = true; w("rc4_bilet_sayısı   : " .. S.krb_etype23) end
  local itun = topN(S.icmp_tunnel_hits, 2, 3)
  for _, r in ipairs(itun) do ioc = true; w("icmp_tünel_ident   : " .. r[1] .. " (" .. r[2] .. " echo)") end
  if S.frag_conflict_n > 0 then ioc = true; w("fragment_overlap   : " .. S.frag_overlap_n .. " (conflict: " .. S.frag_conflict_n .. ")") end
  local svs = topN(S.svcctl_srcs, 2, 2)
  for _, r in ipairs(svs) do ioc = true; w("svcctl_kaynağı     : " .. r[1]) end
  if S.deauth > 0 then ioc = true; w("wlan_deauth        : " .. S.deauth .. " çerçeve") end
  if not ioc then w("(belirgin IOC bulunamadı)") end
  w("```")
  w("")
  w("---")
  w("_Bulgular, yukarıdaki filtrelerle Wireshark'ta teyit edilebilir._")

  return table.concat(L, "\n")
end

-- ═════════════════════════ ÇIKIŞ ══════════════════════════════════════
-- JSON yan çıktı: IOC + özet (SIEM'e aktarım). MD ile aynı dizine <ad>.json
local function write_json(pcap)
  local ok2, err2 = pcall(function()
    local function jstr(s) s = tostring(s or "") return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', ' ') .. '"' end
    local function jarr_string(t, n)
      local out, cnt = {}, 0
      for k in pairs(t) do cnt = cnt + 1; if not n or cnt <= n then out[#out+1] = jstr(k) end end
      return "[" .. table.concat(out, ",") .. "]"
    end
    local scans = port_scan_analysis()
    local beacons = beacon_analysis()
    local L = {}
    L[#L+1] = "{"
    L[#L+1] = '  "pcap": ' .. jstr(pcap and pcap:match("([^/\\]+)$") or "capture") .. ","
    L[#L+1] = '  "packets": ' .. S.pkts .. ","
    L[#L+1] = '  "iocs": {'
    L[#L+1] = '    "scan_sources": ' .. (function()
      local o = {}
      for i = 1, math.min(#scans, 5) do o[i] = jstr(scans[i].src) end
      return "[" .. table.concat(o, ",") .. "]"
    end)() .. ","
    L[#L+1] = '    "c2_channels": ' .. (function()
      local o = {}
      for i = 1, math.min(#beacons, 5) do o[i] = jstr(beacons[i].key) end
      return "[" .. table.concat(o, ",") .. "]"
    end)() .. ","
    L[#L+1] = '    "dns_tunnel_queries": ' .. jarr_string((function()
      local t = {}
      for i = 1, math.min(#S.dns_long_labels, 5) do t[S.dns_long_labels[i]] = true end
      return t
    end)(), 5) .. ","
    L[#L+1] = '    "icmp_tunnel_idents": ' .. jarr_string(S.icmp_tunnel_hits, 3) .. ","
    L[#L+1] = '    "rc4_tickets": ' .. S.krb_etype23 .. ","
    L[#L+1] = '    "null_smb_sessions": ' .. S.ntlm_null .. ","
    L[#L+1] = '    "smb_badname_trees": ' .. jarr_string(S.smb2_badname, 3) .. ","
    L[#L+1] = '    "fragment_overlaps": ' .. S.frag_overlap_n .. ","
    L[#L+1] = '    "leaked_credentials": ' .. (function()
      local o = {}
      for i = 1, math.min(#S.creds, 5) do o[i] = jstr(S.creds[i].data) end
      return "[" .. table.concat(o, ",") .. "]"
    end)() .. ","
    L[#L+1] = '    "ntlm_accounts": ' .. jarr_string(S.ntlm_users, 5) .. ","
    L[#L+1] = '    "fake_user_agents": ' .. jarr_string((function()
      local t = {}
      if S.fake_uas then for i = 1, math.min(#S.fake_uas, 3) do t[S.fake_uas[i].ua] = true end end
      return t
    end)(), 3)
    L[#L+1] = '  }'
    L[#L+1] = "}"
    local base = pcap:gsub("%.[^.]+$", "")
    local f = io.open(base .. ".json", "w")
    if not f then error("json yazılamıyor") end
    f:write(table.concat(L, "\n"))
    f:close()
  end)
  if not ok2 then
    io.write("[shark-tank] JSON HATASI: " .. tostring(err2) .. "\n")
    io.flush()
  end
end

local function write_report()
  local ok, err = pcall(function()
    local pcap = nil
    if os and os.getenv then pcap = os.getenv("SHARK_TANK_PCAP") end
    if not pcap then
      -- tshark çalışma dizini + tek dosya varsayımı: cwd'deki ilk argüman yoksa
      pcap = (arg and arg[1]) or "capture.pcap"
    end
    local base = pcap:gsub("%.[^.]+$", "")
    local out = base .. ".md"
    local f = io.open(out, "w")
    if not f then error("yazılamıyor: " .. out) end
    f:write(build_report(pcap))
    f:close()
    if os and os.getenv and os.getenv("SHARK_TANK_JSON") == "1" then
      write_json(pcap)
    end
    if os and os.getenv and os.getenv("SHARK_TANK_QUIET") ~= "1" then
      io.write("[shark-tank] rapor yazildi: " .. out .. "\n")
      io.flush()
    end
  end)
  if not ok then
    io.write("[shark-tank] RAPOR HATASI: " .. tostring(err) .. "\n")
    io.flush()
  end
end

-- ═════════════════════════ TAP ═══════════════════════════════════════
init_fields()
reset_state()

local tap = Listener.new("frame")

-- SAMR sayacı: ayrı filtreli listener (heuristic dissector protocols'a düşmez)
local samr_tap = Listener.new("frame", "samr")
function samr_tap.packet(pinfo)
  local fs = fi_samr_src and fi_samr_src()
  if fs then inc(S.samr_srcs, tostring(fs.value)) end
end

-- svcctl sayacı: PsExec ayak izi (aynı sebeple ayrı listener)
local svcctl_tap = Listener.new("frame", "svcctl")
function svcctl_tap.packet(pinfo)
  local fs = fi_samr_src and fi_samr_src()
  if fs then inc(S.svcctl_srcs, tostring(fs.value)) end
end

function tap.packet(pinfo, tvb, userdata)
  local ok, err = pcall(analyze_packet, pinfo)
  if not ok then
    -- tek paket hatası tüm analizi durdurmasın
  end
end

function tap.draw()
  -- tshark dosya sonunda draw() çağırır: raporu yaz
  if gui and gui.enabled and gui.enabled() then
    -- GUI modunda menü kullanılır
  else
    write_report()
  end
end

-- GUI desteği: Wireshark menüsü (Tools > Shark-Tank)
if gui and gui.enabled and gui.enabled() then
  register_menu("Shark-Tank/Rapor Üret", function()
    -- Geçici yüklemede (File > Run Lua Script) tap'lar dosya başını
    -- kaçırmış olabilir: durumu sıfırla, dosyayı baştan işlet, sonra göster.
    reset_state()
    init_fields()
    retap()
    local win = TextWindow.new("Shark-Tank Rapor (v" .. ST.version .. ")")
    win:set(build_report(nil))
  end, MENU_TOOLS_UNSORTED)
end
