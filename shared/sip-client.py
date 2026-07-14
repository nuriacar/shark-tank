#!/usr/bin/env python3
"""
Minimal SIP client for Shark-Tank VoIP lab traffic generation.
Sends SIP REGISTER, INVITE, BYE with Digest MD5 auth.
"""
import socket
import hashlib
import os
import sys
import time

VOIP_IP = "172.50.2.22"
VOIP_PORT = 5060
CLIENT_IP = "172.50.2.100"
CLIENT_PORT = 5060
DOMAIN = "172.50.2.22"

EXT = sys.argv[1] if len(sys.argv) > 1 else "1000"
PASS = sys.argv[2] if len(sys.argv) > 2 else "voip123"
TARGET = sys.argv[3] if len(sys.argv) > 3 else "1001"

CALL_ID = f"{int(time.time())}@client"
BRANCH = f"z9hG4bK{int(time.time())}"
BRANCH2 = f"z9hG4bK{int(time.time()) + 1}"
TAG = EXT

def md5(data):
    return hashlib.md5(data.encode()).hexdigest()

def calc_response(nonce, uri, method, realm, qop=None, nc="00000001", cnonce=""):
    ha1 = md5(f"{EXT}:{realm}:{PASS}")
    ha2 = md5(f"{method}:{uri}")
    if qop:
        return md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return md5(f"{ha1}:{nonce}:{ha2}")

def parse_auth_params(resp):
    params = {}
    for line in resp.split("\r\n"):
        if line.lower().startswith("www-authenticate"):
            for part in line.split(","):
                part = part.strip()
                if "=" in part:
                    key, val = part.split("=", 1)
                    key = key.split()[-1].strip().lower()
                    val = val.strip('"').strip()
                    params[key] = val
    return params

def send_msg(sock, msg):
    sock.sendto(msg.encode(), (VOIP_IP, VOIP_PORT))
    print(f"  Gönderildi: {msg.split(chr(13))[0]}")
    try:
        sock.settimeout(3.0)
        data, addr = sock.recvfrom(4096)
        text = data.decode(errors="replace")
        print(f"  Alındı: {text.split(chr(13))[0]}")
        return text
    except socket.timeout:
        print("  (yanıt gelmedi)")
        return ""

def recv_responses(sock, wait_for_final=True, timeout=5.0):
    """Read SIP responses until a final response (2xx/4xx/5xx) or timeout."""
    sock.settimeout(timeout)
    deadline = time.time() + timeout
    last_resp = ""
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            text = data.decode(errors="replace")
            first_line = text.split(chr(13))[0]
            print(f"  Alındı: {first_line}")
            last_resp = text
            if " 2" in first_line or " 4" in first_line or " 5" in first_line or " 6" in first_line:
                break
        except socket.timeout:
            break
    return last_resp

def make_auth_header(params, uri, method):
    nonce = params.get("nonce", "")
    realm = params.get("realm", DOMAIN)
    qop = params.get("qop")
    cnonce = md5(f"{EXT}:{int(time.time())}")[:16] if qop else ""
    nc = "00000001"
    response = calc_response(nonce, uri, method, realm, qop, nc, cnonce)
    hdr = f'Digest username="{EXT}",realm="{realm}",nonce="{nonce}",uri="{uri}",response="{response}",algorithm=MD5'
    if qop:
        hdr += f',qop={qop},nc={nc},cnonce="{cnonce}"'
    if "opaque" in params:
        hdr += f',opaque="{params["opaque"]}"'
    return hdr

def register(sock):
    uri = f"sip:{DOMAIN}"
    via = f"SIP/2.0/UDP {CLIENT_IP}:{CLIENT_PORT};branch={BRANCH}"
    msg = (
        f"REGISTER {uri} SIP/2.0\r\n"
        f"Via: {via}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{EXT}@{DOMAIN}>;tag={TAG}\r\n"
        f"To: <sip:{EXT}@{DOMAIN}>\r\n"
        f"Call-ID: {CALL_ID}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{EXT}@{CLIENT_IP}:{CLIENT_PORT}>\r\n"
        f"Expires: 3600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    resp = send_msg(sock, msg)

    if "401 Unauthorized" in resp or "407 Proxy" in resp:
        params = parse_auth_params(resp)
        nonce = params.get("nonce", "")
        if nonce:
            auth_hdr = make_auth_header(params, uri, "REGISTER")
            msg2 = (
                f"REGISTER {uri} SIP/2.0\r\n"
                f"Via: {via}\r\n"
                f"Max-Forwards: 70\r\n"
                f"From: <sip:{EXT}@{DOMAIN}>;tag={TAG}\r\n"
                f"To: <sip:{EXT}@{DOMAIN}>\r\n"
                f"Call-ID: {CALL_ID}\r\n"
                f"CSeq: 2 REGISTER\r\n"
                f"Contact: <sip:{EXT}@{CLIENT_IP}:{CLIENT_PORT}>\r\n"
                f"Authorization: {auth_hdr}\r\n"
                f"Expires: 3600\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            resp = send_msg(sock, msg2)
    return resp

def invite(sock, target=TARGET):
    uri = f"sip:{target}@{DOMAIN}"
    via = f"SIP/2.0/UDP {CLIENT_IP}:{CLIENT_PORT};branch={BRANCH2}"
    call_id = f"{int(time.time())}call@client"
    body = (
        "v=0\r\n"
        f"o=user 0 0 IN IP4 {CLIENT_IP}\r\n"
        "s=session\r\n"
        f"c=IN IP4 {CLIENT_IP}\r\n"
        "t=0 0\r\n"
        "m=audio 10002 RTP/AVP 0 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
    )
    msg = (
        f"INVITE {uri} SIP/2.0\r\n"
        f"Via: {via}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{EXT}@{DOMAIN}>;tag={TAG}invite\r\n"
        f"To: <sip:{target}@{DOMAIN}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:{EXT}@{CLIENT_IP}:{CLIENT_PORT}>\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
        f"{body}"
    )
    resp = send_msg(sock, msg)
    if "401 Unauthorized" in resp or "407 Proxy" in resp:
        params = parse_auth_params(resp)
        nonce = params.get("nonce", "")
        if nonce:
            auth_hdr = make_auth_header(params, uri, "INVITE")
            msg2 = (
                f"INVITE {uri} SIP/2.0\r\n"
                f"Via: {via}\r\n"
                f"Max-Forwards: 70\r\n"
                f"From: <sip:{EXT}@{DOMAIN}>;tag={TAG}invite\r\n"
                f"To: <sip:{target}@{DOMAIN}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: 2 INVITE\r\n"
                f"Contact: <sip:{EXT}@{CLIENT_IP}:{CLIENT_PORT}>\r\n"
                f"Authorization: {auth_hdr}\r\n"
                f"Content-Type: application/sdp\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                f"{body}"
            )
            sock.sendto(msg2.encode(), (VOIP_IP, VOIP_PORT))
            print(f"  Gönderildi: {msg2.split(chr(13))[0]}")
            resp = recv_responses(sock)
    return resp, call_id

def ack(sock, target=TARGET, call_id=""):
    uri = f"sip:{target}@{DOMAIN}"
    msg = (
        f"ACK {uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {CLIENT_IP}:{CLIENT_PORT};branch={BRANCH2}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{EXT}@{DOMAIN}>;tag={TAG}invite\r\n"
        f"To: <sip:{target}@{DOMAIN}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 ACK\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    send_msg(sock, msg)

def bye(sock, target=TARGET, call_id=""):
    uri = f"sip:{target}@{DOMAIN}"
    msg = (
        f"BYE {uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {CLIENT_IP}:{CLIENT_PORT};branch={BRANCH2}_bye\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{EXT}@{DOMAIN}>;tag={TAG}invite\r\n"
        f"To: <sip:{target}@{DOMAIN}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 2 BYE\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    send_msg(sock, msg)

if __name__ == "__main__":
    action = sys.argv[4] if len(sys.argv) > 4 else "full"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((CLIENT_IP, CLIENT_PORT))

    print(f"=== SIP İstemci {EXT}:{PASS} → {TARGET} ({action}) ===")

    if action in ("register", "full"):
        print(f"\n[1/3] REGISTER {EXT}@{DOMAIN}")
        register(sock)

    if action in ("full",):
        print(f"\n[2/3] INVITE {EXT} → {TARGET}")
        time.sleep(0.5)
        resp, call_id = invite(sock)
        if "180 Ringing" in resp or "200 OK" in resp or "183 Session" in resp:
            print("  Çağrı kuruldu, ACK gönderiliyor...")
            ack(sock, TARGET, call_id)

            print(f"\n[3/3] BYE — çağrıyı sonlandır")
            time.sleep(2)
            bye(sock, TARGET, call_id)

    sock.close()
    print("=== Tamamlandı ===")
