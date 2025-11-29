#!/usr/bin/env python3
"""
Educational Packet Sniffer / Analyzer using Scapy.
Usage examples:
  sudo python3 packet_sniffer.py                 # sniff default iface, all packets
  sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80" -w capture.pcap -c 100
"""

import argparse
import datetime
import sys
from collections import Counter
from scapy.all import sniff, wrpcap, Raw, IP, IPv6, TCP, UDP, ICMP, Ether

# Max payload bytes to display
PAYLOAD_PREVIEW_LEN = 64

proto_counter = Counter()

def pretty_payload(pkt):
    """Return a readable preview of payload as ASCII (non-printable -> dot) and hex."""
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
        preview = raw[:PAYLOAD_PREVIEW_LEN]
        # ASCII-safe
        ascii_preview = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in preview)
        hex_preview = preview.hex()
        if len(raw) > PAYLOAD_PREVIEW_LEN:
            ascii_preview += '...'
            hex_preview = hex_preview[:PAYLOAD_PREVIEW_LEN*2] + '...'
        return ascii_preview, hex_preview
    return "", ""

def extract_ip_info(pkt):
    """Safely extract source/destination and protocol name."""
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        return src, dst, proto
    if IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        proto = pkt[IPv6].nh
        return src, dst, proto
    # non-IP packets
    if Ether in pkt:
        return pkt[Ether].src, pkt[Ether].dst, "ETH"
    return "?", "?", "?"

def proto_name(pkt):
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if IP in pkt or IPv6 in pkt:
        return "IP"
    return pkt.__class__.__name__

def on_packet(pkt, args):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    src, dst, proto_field = extract_ip_info(pkt)
    pname = proto_name(pkt)
    length = len(pkt)
    ascii_preview, hex_preview = pretty_payload(pkt)

    # Count protocols
    proto_counter[pname] += 1

    # Print summary
    print(f"[{ts}] {pname:5} {src:>21} -> {dst:<21} len={length:4}", end='')
    if ascii_preview:
        print(f" payload='{ascii_preview}'")
    else:
        print("")

    # Optional detailed debug (toggle with -v)
    if args.verbose:
        print(f"    scapy_summary: {pkt.summary()}")
        if hex_preview:
            print(f"    payload (hex preview): {hex_preview}")

    # Write to pcap buffer if writing is enabled
    if args.write:
        args._pcap_buffer.append(pkt)

    # If max count reached stop
    if args.count and sum(proto_counter.values()) >= args.count:
        return True  # stop sniff

def print_stats():
    print("\n--- Summary ---")
    total = sum(proto_counter.values())
    print(f"Captured packets: {total}")
    for p, c in proto_counter.most_common():
        print(f"  {p:6}: {c}")

def main():
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer/Analyzer (Scapy)")
    parser.add_argument("-i", "--iface", help="Network interface to sniff (default: first)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g. 'tcp port 80')", default=None)
    parser.add_argument("-w", "--write", help="Write capture to pcap file", default=None)
    parser.add_argument("-c", "--count", type=int, help="Stop after COUNT packets", default=0)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # prepare args for callback use
    args._pcap_buffer = []  # store packets to write later

    print("Starting sniffing. Press Ctrl+C to stop (requires admin/root).")
    if args.filter:
        print(f"Filter: {args.filter}")
    if args.iface:
        print(f"Interface: {args.iface}")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=lambda pkt: on_packet(pkt, args),
            store=False,
            stop_filter=lambda x: sum(proto_counter.values()) >= args.count if args.count else False
        )
    except PermissionError:
        print("Permission error: run as root/Administrator (on Windows, run PowerShell as Administrator).", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print(f"\nError while sniffing: {e}", file=sys.stderr)
    finally:
        # Write pcap file if requested
        if args.write:
            try:
                wrpcap(args.write, args._pcap_buffer)
                print(f"Wrote {len(args._pcap_buffer)} packets to {args.write}")
            except Exception as e:
                print(f"Failed to write pcap: {e}", file=sys.stderr)

        print_stats()

if __name__ == "__main__":
    main()
