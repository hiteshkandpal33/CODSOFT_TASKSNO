# Task 1 – Network Packet Analyzer

A command-line packet analyzer written in Python using only the standard library (`socket`, `struct`). It captures packets from the network (or reads a `.pcap` file), decodes each layer by hand, and prints an organised table plus a summary report.

## Features
- **Live capture** with raw sockets (Linux `AF_PACKET`; Windows `SIO_RCVALL`) – needs root/Administrator
- **Offline analysis** of classic `.pcap` files (Ethernet)
- Decodes **Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6, DNS**
- Extracts **source/destination IP and port, protocol, TTL, TCP flags, sequence numbers, service name, DNS query** and the **payload** (hex + ASCII with `-v`)
- Filters: `--proto`, `--ip`, `--port`, `-c` (packet count)
- Summary: protocol mix, top talkers/destinations/ports; export to **JSON** and **CSV**

## Usage
```bash
python3 make_sample_pcap.py                       # creates sample.pcap (synthetic traffic, no root needed)
python3 packet_analyzer.py --read sample.pcap -v  # analyse it, with payload dumps
python3 packet_analyzer.py --read sample.pcap --proto dns
python3 packet_analyzer.py --read sample.pcap --json out.json --csv out.csv

sudo python3 packet_analyzer.py --live -c 20             # live capture, 20 packets
sudo python3 packet_analyzer.py --live --proto tcp --port 443 -v
```
See `sample_output.txt` for example output.

## How it works
1. A raw socket (or pcap file) provides complete Ethernet frames.
2. `decode_packet()` reads the Ethernet header, picks the network layer from the EtherType, then `decode_transport()` parses TCP/UDP/ICMP using `struct.unpack` with the header layouts from the RFCs.
3. UDP port 53 payloads are parsed as DNS (including name compression).
4. Packets passing the filters are printed and collected for the summary/exports.

## Notes
- Why not Scapy? The task allows Scapy *or* Socket. Writing the decoders yourself shows exactly how the protocols are structured. (You can compare results against Wireshark or Scapy.)
- Not supported: pcapng files, VLAN tags, IPv6 extension headers, TCP stream reassembly.
- Use only on networks you own or are authorised to monitor.
