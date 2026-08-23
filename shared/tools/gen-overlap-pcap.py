#!/usr/bin/env python3
"""m06 fragment-overlap pcap üretici.

Docker bridge netfilter, MF bayraklı raw paketleri düştüğü için overlap
zinciri doğrudan pcap dosyası olarak üretilir ve generate-traffic.sh
tarafından module-06 pcap'ine zaman sırasıyla birleştirilir.

Kullanım:
  gen-overlap-pcap.py <çıktı.pcap> <src-mac> <dst-mac>
"""
import struct, sys, time

def cksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def eth(smac, dmac, etype=0x0800):
    return bytes.fromhex(dmac.replace(':', '')) + bytes.fromhex(smac.replace(':', '')) + struct.pack('!H', etype)

def frag_ip(src, dst, ident, offset_bytes, mf, payload):
    flags_frag = (offset_bytes // 8) | (0x2000 if mf else 0)
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, ident, flags_frag,
                      64, 17, 0,
                      bytes(int(x) for x in src.split('.')),
                      bytes(int(x) for x in dst.split('.')))
    hdr = hdr[:10] + struct.pack('!H', cksum(hdr)) + hdr[12:]
    return hdr + payload

def main():
    out, smac, dmac = sys.argv[1], sys.argv[2], sys.argv[3]
    src, dst = '172.50.2.200', '172.50.2.100'
    ident = 0x7771
    udp = struct.pack('!HHHH', 45000, 9090, 8 + 1600, 0) + b'E' * 1600

    frames = [
        frag_ip(src, dst, ident, 0,    True,  udp[:1480]),   # ilk parça 0..1480
        frag_ip(src, dst, ident, 1000, True,  b'F' * 1400),  # OVERLAP: 1000..2400
        frag_ip(src, dst, ident, 2400, False, b'G' * 200),   # kuyruk 2400..2600
    ]

    with open(out, 'wb') as f:
        # klasik pcap başlığı (LINKTYPE_ETHERNET=1)
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        base = time.time()
        for i, pkt in enumerate(frames):
            frame = eth(smac, dmac) + pkt
            ts = base + i * 0.2
            sec, usec = int(ts), int((ts % 1) * 1e6)
            f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)))
            f.write(frame)
    print('overlap pcap yazildi: %s (%d frame)' % (out, len(frames)))

if __name__ == '__main__':
    main()
