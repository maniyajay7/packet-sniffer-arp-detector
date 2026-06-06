#!/usr/bin/env python3
# =============================================================
# main.py
# Advanced Packet Sniffer + ARP Spoofing Detector
# =============================================================
# Entry-point for the CLI tool.
#
# Usage examples:
#   python main.py --live --interface eth0
#   python main.py --live --interface Wi-Fi
#   python main.py --pcap sample.pcap
#   python main.py --live --interface eth0 --save output.pcap
#   python main.py --live --interface eth0 --verbose
#   python main.py --list-interfaces
#
# Run  python main.py -h  for full help.
# =============================================================

import argparse
import sys

# Initialise colorama for cross-platform coloured output
from colorama import init as colorama_init
colorama_init(autoreset=False)

from modules.utils import print_banner, print_ethical_notice, list_interfaces
from modules.sniffer import PacketSniffer
from modules.logger import log_info, log_error


# ------------------------------------------------------------------
# Argument Parser
# ------------------------------------------------------------------

def build_parser():
    """
    Build and return the argparse.ArgumentParser with all CLI
    options for the tool.

    Returns:
        argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="packet-sniffer-arp-detector",
        description=(
            "Advanced Packet Sniffer + ARP Spoofing Detector — "
            "a defensive network monitoring tool built with Scapy."
        ),
        epilog=(
            "ETHICAL NOTICE: Only use this tool on networks you own "
            "or have explicit permission to monitor."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Mode selection (mutually exclusive) ---
    mode_group = parser.add_mutually_exclusive_group(required=False)

    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Start live packet capture on a network interface.",
    )

    mode_group.add_argument(
        "--pcap",
        type=str,
        metavar="FILE",
        help="Analyse packets from an existing PCAP file.",
    )

    mode_group.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )

    # --- Options ---
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g. eth0, Wi-Fi).",
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited). Default: 0.",
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=None,
        help="Stop capture after N seconds.",
    )

    parser.add_argument(
        "-s", "--save",
        type=str,
        metavar="FILE",
        default=None,
        help="Save captured packets to a PCAP file.",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print every captured packet to the terminal.",
    )

    return parser


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    """
    Main entry-point:
        1. Parse CLI arguments.
        2. Show banner and ethical notice.
        3. Dispatch to the appropriate mode (live / pcap / list).
    """
    parser = build_parser()
    args = parser.parse_args()

    # Show banner and ethical reminder
    print_banner()
    print_ethical_notice()

    # ----------------------------------------------------------
    # Mode: List interfaces
    # ----------------------------------------------------------
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # ----------------------------------------------------------
    # Mode: PCAP file analysis
    # ----------------------------------------------------------
    if args.pcap:
        log_info(f"Mode: PCAP file analysis ({args.pcap})")
        sniffer = PacketSniffer(
            verbose=args.verbose,
            save_path=args.save,
        )
        sniffer.analyse_pcap(args.pcap)
        sys.exit(0)

    # ----------------------------------------------------------
    # Mode: Live capture
    # ----------------------------------------------------------
    if args.live:
        if not args.interface:
            log_error("Live capture requires --interface. Example:")
            print("  python main.py --live --interface eth0")
            print("  python main.py --live --interface Wi-Fi\n")
            print("Use --list-interfaces to see available interfaces.\n")
            sys.exit(1)

        log_info(f"Mode: Live capture on {args.interface}")
        sniffer = PacketSniffer(
            interface=args.interface,
            verbose=args.verbose,
            save_path=args.save,
        )
        sniffer.start_live_capture(
            count=args.count,
            timeout=args.timeout,
        )
        sys.exit(0)

    # ----------------------------------------------------------
    # No mode selected — show help
    # ----------------------------------------------------------
    print(
        "No mode selected. Use --live, --pcap, or --list-interfaces.\n"
    )
    parser.print_help()
    sys.exit(1)


# Standard Python entry-point guard
if __name__ == "__main__":
    main()
