#!/usr/bin/env python3
"""
CodSoft Cyber Security Internship - Task 1: Network Packet Analyzer
===================================================================
Captures packets (live, using raw sockets) or reads a .pcap file, decodes the
Ethernet / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / DNS layers by hand, and prints
source IP, destination IP, protocol, ports, flags and a payload preview in an
organised table, followed by a summary report.

Only the Python standard library is used (socket, struct), so it runs anywhere.

Usage examples
--------------
  sudo python3 packet_analyzer.py --live -c 20            # live capture (needs root/admin)
  sudo python3 packet_analyzer.py --live --proto tcp --port 443
  python3 packet_analyzer.py --read sample.pcap -v        # analyse an existing pcap
  python3 packet_analyzer.py --read sample.pcap --json out.json --csv out.csv

Use only on networks you own or are authorised to monitor.
"""
import argparse
import csv
import ipaddress
import json
import socket
import struct
import sys
import time
from collections import Counter

ETH_IPV4, ETH_ARP, ETH_IPV6 = 0x0800, 0x0806, 0x86DD
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"),
             (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
WELL_KNOWN = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
              53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
              123: "NTP", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------
def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def parse_dns_name(data, offset):
    labels, jumped, end, hops = [], False, offset, 0
    while offset < len(data) and hops < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:          # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped, hops = ptr, True, hops + 1
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (end if jumped else offset)


def parse_dns(payload):
    if len(payload) < 12:
        return None
    tid, flags, qd, an = struct.unpack("!HHHH", payload[:8])
    info = {"dns_id": tid, "dns_type": "response" if flags & 0x8000 else "query"}
    if qd:
        name, off = parse_dns_name(payload, 12)
        if off + 4 <= len(payload):
            qtype = struct.unpack("!H", payload[off:off + 2])[0]
            info["dns_query"] = name
            info["dns_qtype"] = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX",
                                 16: "TXT", 2: "NS"}.get(qtype, str(qtype))
    info["dns_answers"] = an
    return info


def decode_transport(proto, data, pkt):
    """Fill pkt with TCP/UDP/ICMP details; return the application payload."""
    if proto == 6 and len(data) >= 20:
        sport, dport, seq, ack, off_flags, win = struct.unpack("!HHIIHH", data[:16])
        hlen = (off_flags >> 12) * 4
        flags = [n for bit, n in TCP_FLAGS if off_flags & bit]
        pkt.update(src_port=sport, dst_port=dport, seq=seq, ack=ack,
                   flags="|".join(flags) or "-", window=win)
        return data[hlen:]
    if proto == 17 and len(data) >= 8:
        sport, dport, length = struct.unpack("!HHH", data[:6])
        pkt.update(src_port=sport, dst_port=dport, udp_len=length)
        return data[8:]
    if proto in (1, 58) and len(data) >= 4:
        t, c = struct.unpack("!BB", data[:2])
        names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                 11: "Time Exceeded"} if proto == 1 else {128: "Echo Request", 129: "Echo Reply"}
        pkt.update(icmp_type=t, icmp_code=c, icmp_desc=names.get(t, "Other"))
        return data[4:]
    return data


def decode_packet(raw, ts=None):
    """Decode a raw Ethernet frame into a dictionary of fields."""
    pkt = {"time": ts or time.time(), "length": len(raw), "protocol": "OTHER",
           "src_ip": "-", "dst_ip": "-", "src_port": None, "dst_port": None,
           "payload": b""}
    if len(raw) < 14:
        pkt["protocol"] = "MALFORMED"
        return pkt
    dst_mac, src_mac, etype = struct.unpack("!6s6sH", raw[:14])
    pkt.update(src_mac=mac(src_mac), dst_mac=mac(dst_mac))
    body = raw[14:]

    if etype == ETH_IPV4 and len(body) >= 20:
        ihl = (body[0] & 0x0F) * 4
        ttl, proto = body[8], body[9]
        pkt.update(src_ip=socket.inet_ntoa(body[12:16]),
                   dst_ip=socket.inet_ntoa(body[16:20]), ttl=ttl,
                   protocol=PROTO_NAMES.get(proto, f"IP-{proto}"))
        pkt["payload"] = decode_transport(proto, body[ihl:], pkt)
    elif etype == ETH_IPV6 and len(body) >= 40:
        nxt, hop = body[6], body[7]
        pkt.update(src_ip=str(ipaddress.IPv6Address(body[8:24])),
                   dst_ip=str(ipaddress.IPv6Address(body[24:40])), ttl=hop,
                   protocol=PROTO_NAMES.get(nxt, f"IPv6-{nxt}"))
        pkt["payload"] = decode_transport(nxt, body[40:], pkt)
    elif etype == ETH_ARP and len(body) >= 28:
        op = struct.unpack("!H", body[6:8])[0]
        pkt.update(protocol="ARP", src_ip=socket.inet_ntoa(body[14:18]),
                   dst_ip=socket.inet_ntoa(body[24:28]),
                   arp_op="request" if op == 1 else "reply" if op == 2 else str(op))
    # application-layer hints
    ports = {pkt["src_port"], pkt["dst_port"]}
    if pkt["protocol"] == "UDP" and 53 in ports:
        d = parse_dns(pkt["payload"])
        if d:
            pkt.update(d)
            pkt["protocol"] = "DNS"
    elif pkt["protocol"] == "TCP":
        for p in ports:
            if p in WELL_KNOWN:
                pkt["service"] = WELL_KNOWN[p]
                break
    elif pkt["protocol"] == "UDP":
        for p in ports:
            if p in WELL_KNOWN:
                pkt["service"] = WELL_KNOWN[p]
                break
    return pkt


# --------------------------------------------------------------------------
# Input: pcap reader and live sniffer
# --------------------------------------------------------------------------
def read_pcap(path):
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise ValueError("file too short to be a pcap")
        magic = head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise ValueError("not a classic pcap file (pcapng is not supported)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", head[20:24])[0]
        if linktype != 1:
            raise ValueError(f"unsupported link type {linktype}; only Ethernet (1)")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, caplen, _ = struct.unpack(end + "IIII", h)
            data = f.read(caplen)
            yield sec + frac / (1e9 if nano else 1e6), data


def live_capture(iface=None):
    """Yield (timestamp, frame) from a raw socket. Needs root / Administrator."""
    if sys.platform.startswith("linux"):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if iface:
            s.bind((iface, 0))
        while True:
            yield time.time(), s.recvfrom(65535)[0]
    elif sys.platform == "win32":
        host = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        while True:   # Windows gives IP packets without an Ethernet header
            yield time.time(), b"\x00" * 12 + b"\x08\x00" + s.recvfrom(65535)[0]
    else:
        raise OSError("Live capture is supported on Linux and Windows only; use --read")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def hexdump(data, limit=64):
    out = []
    data = data[:limit]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"      {i:04x}  {hx}  {asc}")
    return "\n".join(out)


def matches(pkt, args):
    if args.proto and pkt["protocol"].lower() != args.proto.lower() and \
            not (args.proto.lower() == "udp" and pkt["protocol"] == "DNS"):
        return False
    if args.ip and args.ip not in (pkt["src_ip"], pkt["dst_ip"]):
        return False
    if args.port and args.port not in (pkt["src_port"], pkt["dst_port"]):
        return False
    return True


HEADER = f"{'#':>4}  {'TIME':<12} {'PROTO':<7} {'SOURCE':<22} {'DESTINATION':<22} {'LEN':>5}  INFO"


def endpoint(ip, port):
    return f"{ip}:{port}" if port is not None else ip


def info_text(p):
    if p["protocol"] == "DNS":
        return f"{p.get('dns_type')} {p.get('dns_qtype', '')} {p.get('dns_query', '')}".strip()
    if p["protocol"] == "TCP":
        return f"[{p.get('flags')}] seq={p.get('seq')} win={p.get('window')} {p.get('service', '')}".strip()
    if p["protocol"].startswith("ICMP"):
        return p.get("icmp_desc", "")
    if p["protocol"] == "ARP":
        return f"ARP {p.get('arp_op')}"
    if p["protocol"] == "UDP":
        return f"len={p.get('udp_len')} {p.get('service', '')}".strip()
    return ""


def print_row(n, p, verbose):
    t = time.strftime("%H:%M:%S", time.localtime(p["time"]))
    print(f"{n:>4}  {t:<12} {p['protocol']:<7} "
          f"{endpoint(p['src_ip'], p['src_port']):<22} "
          f"{endpoint(p['dst_ip'], p['dst_port']):<22} {p['length']:>5}  {info_text(p)}")
    if verbose and p["payload"]:
        print(hexdump(p["payload"]))


def print_summary(pkts):
    print("\n" + "=" * 70)
    print(f"SUMMARY: {len(pkts)} packets, {sum(p['length'] for p in pkts)} bytes")
    print("=" * 70)
    print("Protocols :", ", ".join(f"{k}={v}" for k, v in Counter(p["protocol"] for p in pkts).most_common()))
    print("Top talkers (source IP):")
    for ip, c in Counter(p["src_ip"] for p in pkts).most_common(5):
        print(f"   {ip:<40} {c} pkts")
    print("Top destinations:")
    for ip, c in Counter(p["dst_ip"] for p in pkts).most_common(5):
        print(f"   {ip:<40} {c} pkts")
    ports = Counter(p["dst_port"] for p in pkts if p["dst_port"] is not None)
    if ports:
        print("Top destination ports:", ", ".join(
            f"{k}({WELL_KNOWN.get(k, '?')})={v}" for k, v in ports.most_common(5)))


def export(pkts, args):
    rows = [{k: (v.hex()[:128] if k == "payload" else v) for k, v in p.items()} for p in pkts]
    if args.json:
        with open(args.json, "w") as f:
            json.dump(rows, f, indent=2, default=str)
        print(f"JSON written to {args.json}")
    if args.csv:
        cols = ["time", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                "length", "flags", "ttl", "service", "dns_query"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"CSV written to {args.csv}")


def main():
    ap = argparse.ArgumentParser(description="Network Packet Analyzer (CodSoft Task 1)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--live", action="store_true", help="capture live (root/admin required)")
    src.add_argument("--read", metavar="PCAP", help="analyse a .pcap file")
    ap.add_argument("-i", "--iface", help="interface for live capture (Linux)")
    ap.add_argument("-c", "--count", type=int, default=0, help="stop after N matching packets")
    ap.add_argument("--proto", help="filter: tcp, udp, icmp, arp, dns ...")
    ap.add_argument("--ip", help="filter: source or destination IP")
    ap.add_argument("--port", type=int, help="filter: source or destination port")
    ap.add_argument("-v", "--verbose", action="store_true", help="show payload hex dump")
    ap.add_argument("--json", help="export results to JSON")
    ap.add_argument("--csv", help="export results to CSV")
    args = ap.parse_args()

    try:
        source = live_capture(args.iface) if args.live else read_pcap(args.read)
        pkts = []
        print(HEADER)
        print("-" * len(HEADER))
        try:
            for ts, raw in source:
                p = decode_packet(raw, ts)
                if not matches(p, args):
                    continue
                pkts.append(p)
                print_row(len(pkts), p, args.verbose)
                if args.count and len(pkts) >= args.count:
                    break
        except KeyboardInterrupt:
            print("\n[!] Capture stopped by user")
    except PermissionError:
        sys.exit("[!] Permission denied: live capture needs root (sudo) or Administrator.")
    except (OSError, ValueError) as e:
        sys.exit(f"[!] {e}")

    if pkts:
        print_summary(pkts)
        export(pkts, args)
    else:
        print("No packets matched.")


if __name__ == "__main__":
    main()
