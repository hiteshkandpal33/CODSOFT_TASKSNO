#!/usr/bin/env python3
"""Builds sample.pcap with synthetic traffic (TCP handshake, HTTP, DNS, ICMP, ARP, UDP)
so the analyzer can be demonstrated without root access or real traffic."""
import socket
import struct
import time


def ip_header(src, dst, proto, payload_len):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, 1, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h


def eth(payload, etype=0x0800, src=b"\xaa\xbb\xcc\x00\x00\x01", dst=b"\xaa\xbb\xcc\x00\x00\x02"):
    return dst + src + struct.pack("!H", etype) + payload


def tcp(sport, dport, flags, seq, data=b""):
    seg = struct.pack("!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | flags, 65535, 0, 0) + data
    return seg


def tcp_pkt(src, dst, sport, dport, flags, seq, data=b""):
    seg = tcp(sport, dport, flags, seq, data)
    return eth(ip_header(src, dst, 6, len(seg)) + seg)


def udp_pkt(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return eth(ip_header(src, dst, 17, len(seg)) + seg)


def dns_query(name, tid=0x1a2b):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def icmp_pkt(src, dst, typ):
    seg = struct.pack("!BBHHH", typ, 0, 0, 1, 1) + b"abcdefgh"
    return eth(ip_header(src, dst, 1, len(seg)) + seg)


def arp_pkt():
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, b"\xaa\xbb\xcc\x00\x00\x01",
                       socket.inet_aton("192.168.1.10"), b"\x00" * 6, socket.inet_aton("192.168.1.1"))
    return eth(body, 0x0806, dst=b"\xff" * 6)


C, S, D = "192.168.1.10", "93.184.216.34", "8.8.8.8"
http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: demo\r\n\r\n"
frames = [
    tcp_pkt(C, S, 51000, 80, 0x02, 100),
    tcp_pkt(S, C, 80, 51000, 0x12, 500),
    tcp_pkt(C, S, 51000, 80, 0x10, 101),
    tcp_pkt(C, S, 51000, 80, 0x18, 101, http),
    tcp_pkt(S, C, 80, 51000, 0x18, 501, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
    udp_pkt(C, D, 40000, 53, dns_query("www.codsoft.in")),
    udp_pkt(C, D, 40001, 53, dns_query("example.com", 0x3c4d)),
    icmp_pkt(C, D, 8),
    icmp_pkt(D, C, 0),
    arp_pkt(),
    udp_pkt(C, "192.168.1.255", 5353, 5353, b"hello-udp"),
    tcp_pkt(C, "203.0.113.5", 52000, 443, 0x02, 900),
    tcp_pkt(C, "203.0.113.5", 52000, 22, 0x02, 901),
]

with open("sample.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    t = time.time()
    for i, fr in enumerate(frames):
        f.write(struct.pack("<IIII", int(t + i * 0.01), int(((t + i * 0.01) % 1) * 1e6), len(fr), len(fr)) + fr)
print(f"sample.pcap written with {len(frames)} packets")
