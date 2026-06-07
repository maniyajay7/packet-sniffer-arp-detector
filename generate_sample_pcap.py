#!/usr/bin/env python3
# =============================================================
# generate_sample_pcap.py
# Safe Test PCAP Generator
# =============================================================
# Creates a sample .pcap file containing:
#   1. Normal ARP traffic (requests and replies)
#   2. Simulated ARP spoofing traffic (MAC address change for
#      the same IP) so that the detector can be demonstrated
#   3. Normal TCP, UDP, and ICMP packets
#
# This script does NOT require elevated privileges because it
# only constructs packets in memory and writes them to a file —
# no packets are sent over the network.
#
# Usage:
#   python generate_sample_pcap.py
#
# Output:
#   samples/sample_traffic.pcap
# =============================================================

import os
from scapy.all import wrpcap, Ether, ARP, IP, TCP, UDP, ICMP

# Output path
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sample_traffic.pcap")


def generate():
    """Build a list of sample packets and write to a PCAP file."""

    packets = []

    # ── 1. Normal ARP Request: Who has 192.168.1.1? ──────────
    packets.append(
        Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:01") /
        ARP(
            op=1,  # ARP Request
            hwsrc="aa:bb:cc:dd:ee:01",
            psrc="192.168.1.10",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
    )

    # ── 2. Normal ARP Reply: 192.168.1.1 is at aa:bb:cc:dd:ee:ff
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:01", src="aa:bb:cc:dd:ee:ff") /
        ARP(
            op=2,  # ARP Reply
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:01",
            pdst="192.168.1.10",
        )
    )

    # ── 3. Some normal IP traffic ─────────────────────────────
    # TCP SYN
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:01") /
        IP(src="192.168.1.10", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="S")
    )

    # UDP DNS-like
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:01") /
        IP(src="192.168.1.10", dst="8.8.8.8") /
        UDP(sport=12345, dport=53)
    )

    # ICMP Echo (ping)
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:01") /
        IP(src="192.168.1.10", dst="192.168.1.1") /
        ICMP(type=8)
    )

    # ── 4. Another normal ARP reply from the gateway ──────────
    # (same IP, same MAC → no alert expected)
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:01", src="aa:bb:cc:dd:ee:ff") /
        ARP(
            op=2,
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:01",
            pdst="192.168.1.10",
        )
    )

    # ── 5. SIMULATED SPOOFING: same IP, DIFFERENT MAC ─────────
    # An attacker claims to be 192.168.1.1 but with MAC 11:22:33:44:55:66
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:01", src="11:22:33:44:55:66") /
        ARP(
            op=2,
            hwsrc="11:22:33:44:55:66",  # ← Different MAC!
            psrc="192.168.1.1",          # ← Same IP as the real gateway
            hwdst="aa:bb:cc:dd:ee:01",
            pdst="192.168.1.10",
        )
    )

    # ── 6. More normal traffic after the spoof ────────────────
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:01") /
        IP(src="192.168.1.10", dst="192.168.1.20") /
        TCP(sport=8080, dport=443, flags="S")
    )

    # ── 7. Second spoofing attempt (yet another MAC) ──────────
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:01", src="de:ad:be:ef:ca:fe") /
        ARP(
            op=2,
            hwsrc="de:ad:be:ef:ca:fe",  # ← Third MAC for 192.168.1.1
            psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:01",
            pdst="192.168.1.10",
        )
    )

    # ── 8. Gratuitous ARP (sender IP == target IP) ────────────
    packets.append(
        Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:02") /
        ARP(
            op=2,
            hwsrc="aa:bb:cc:dd:ee:02",
            psrc="192.168.1.20",
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst="192.168.1.20",  # Same as psrc → gratuitous
        )
    )

    # ── 9. ARP traffic from another device (no spoof) ─────────
    packets.append(
        Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:03") /
        ARP(
            op=1,
            hwsrc="aa:bb:cc:dd:ee:03",
            psrc="192.168.1.30",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
    )

    # ── Write all packets to the PCAP file ────────────────────
    wrpcap(OUTPUT_FILE, packets)
    print(f"[+] Sample PCAP written to: {OUTPUT_FILE}")
    print(f"    Contains {len(packets)} packets including simulated ARP spoofing.")
    print(f"\n    Test with:")
    print(f"      python main.py --pcap {OUTPUT_FILE} --verbose")


if __name__ == "__main__":
    generate()
