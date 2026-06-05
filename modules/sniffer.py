# =============================================================
# modules/sniffer.py
# Packet Sniffer Module
# =============================================================
# Handles two capture modes:
#   1. LIVE capture  — sniffs packets on a given network
#      interface in real-time using Scapy's sniff().
#   2. PCAP analysis — reads a previously captured .pcap file
#      and processes each packet offline.
#
# Every captured packet is:
#   • Summarised and optionally printed (verbose mode)
#   • Passed to the ARP detector if it contains an ARP layer
#   • Optionally saved to a PCAP file for later review
# =============================================================

import os
import sys

from colorama import Fore, Style

# Scapy imports — grouped here for clarity
from scapy.all import sniff, wrpcap, rdpcap, conf
from scapy.layers.l2 import ARP

from modules.arp_detector import ARPDetector
from modules.logger import (
    log_info,
    log_warning,
    log_error,
    log_packet_summary,
    get_log_filepath,
)
from modules.utils import (
    format_packet_summary,
    require_privileges,
    validate_interface,
    list_interfaces,
)


class PacketSniffer:
    """
    Core packet capture and analysis engine.

    Args:
        interface (str | None): Network interface for live capture.
        verbose   (bool)      : Whether to print every packet.
        save_path (str | None): If set, captured packets are also
                                written to this .pcap file.
    """

    def __init__(self, interface=None, verbose=False, save_path=None):
        self.interface = interface
        self.verbose = verbose
        self.save_path = save_path

        # Instantiate the ARP detector
        self.arp_detector = ARPDetector()

        # Packet counters
        self.packet_count = 0
        self.arp_packet_count = 0

        # Buffer for packets to save
        self._capture_buffer = []

    # ----------------------------------------------------------
    # Packet callback (called for each captured packet)
    # ----------------------------------------------------------

    def _process_packet(self, packet):
        """
        Callback invoked by Scapy for every captured packet.

        Steps:
            1. Increment counters.
            2. Build and log a human-readable summary.
            3. If the packet has an ARP layer, pass it to the
               ARP detector for spoofing analysis.
            4. Add the packet to the save buffer if saving is on.

        Args:
            packet: A Scapy packet object.
        """
        self.packet_count += 1

        # --- 1. Build summary ---
        summary = format_packet_summary(packet)

        # --- 2. Log the summary ---
        log_packet_summary(summary, verbose=self.verbose)

        # --- 3. ARP inspection ---
        if packet.haslayer(ARP):
            self.arp_packet_count += 1
            self.arp_detector.inspect_arp_packet(packet)

        # --- 4. Save buffer ---
        if self.save_path:
            self._capture_buffer.append(packet)

    # ----------------------------------------------------------
    # Live Capture
    # ----------------------------------------------------------

    def start_live_capture(self, count=0, timeout=None):
        """
        Begin live packet capture on the configured interface.

        Args:
            count   (int)       : Number of packets to capture.
                                  0 = unlimited (Ctrl+C to stop).
            timeout (int | None): Stop after this many seconds.
        """
        # Ensure we have sufficient privileges for raw sockets
        require_privileges()

        # Validate the interface
        if self.interface and not validate_interface(self.interface):
            log_warning(
                f"Interface '{self.interface}' not found in the system's "
                "interface list. Attempting capture anyway…"
            )
            print(f"\n{Fore.YELLOW}Available interfaces:{Style.RESET_ALL}")
            list_interfaces()

        # Suppress Scapy's default verbose output
        conf.verb = 0

        log_info(
            f"Starting live capture on '{self.interface}' "
            f"(count={count}, timeout={timeout})…"
        )
        print(
            f"{Fore.GREEN}[+] Sniffing on interface: "
            f"{self.interface}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.GREEN}[+] Press Ctrl+C to stop capturing."
            f"{Style.RESET_ALL}\n"
        )

        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                count=count,
                timeout=timeout,
                store=False,          # Don't store in memory (we buffer ourselves)
            )
        except PermissionError:
            log_error(
                "Permission denied. Run as root/Administrator."
            )
            sys.exit(1)
        except OSError as exc:
            log_error(f"OS error during capture: {exc}")
            if "Npcap" in str(exc) or "WinPcap" in str(exc):
                print(
                    f"\n{Fore.YELLOW}[!] It looks like Npcap is not "
                    "installed. Download it from:\n"
                    "    https://npcap.com/#download\n"
                    f"    Install with 'WinPcap API-compatible Mode'.{Style.RESET_ALL}\n"
                )
            sys.exit(1)
        except KeyboardInterrupt:
            # Graceful exit on Ctrl+C
            print(
                f"\n{Fore.YELLOW}[!] Capture stopped by user.{Style.RESET_ALL}"
            )
        finally:
            self._finalise()

    # ----------------------------------------------------------
    # PCAP File Analysis
    # ----------------------------------------------------------

    def analyse_pcap(self, pcap_path):
        """
        Read and analyse packets from an existing PCAP file.

        This does NOT require elevated privileges because no live
        capture takes place.

        Args:
            pcap_path (str): Path to the .pcap file.
        """
        if not os.path.isfile(pcap_path):
            log_error(f"PCAP file not found: {pcap_path}")
            sys.exit(1)

        log_info(f"Reading PCAP file: {pcap_path}")

        try:
            packets = rdpcap(pcap_path)
        except Exception as exc:
            log_error(f"Failed to read PCAP file: {exc}")
            sys.exit(1)

        log_info(f"Loaded {len(packets)} packets from {pcap_path}.")

        for pkt in packets:
            self._process_packet(pkt)

        self._finalise()

    # ----------------------------------------------------------
    # Finalisation — runs after capture or analysis is done
    # ----------------------------------------------------------

    def _finalise(self):
        """
        Post-capture housekeeping:
            1. Save captured packets to a PCAP file (if requested).
            2. Print the ARP table and alert summary.
            3. Print session statistics.
        """
        # Save to PCAP if requested
        if self.save_path and self._capture_buffer:
            try:
                wrpcap(self.save_path, self._capture_buffer)
                log_info(f"Saved {len(self._capture_buffer)} packets to {self.save_path}")
            except Exception as exc:
                log_error(f"Failed to save PCAP: {exc}")

        # Print ARP table and alert summary
        self.arp_detector.print_arp_table()
        self.arp_detector.print_alert_summary()

        # Session statistics
        stats = self.arp_detector.get_stats()
        print(
            f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n"
            f"  Session Statistics\n"
            f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n"
            f"  Total packets processed : {self.packet_count}\n"
            f"  ARP packets analysed    : {self.arp_packet_count}\n"
            f"  Unique IPs in ARP table : {stats['total_ips']}\n"
            f"  Spoofing alerts raised  : {stats['alert_count']}\n"
            f"  Log file                : {get_log_filepath()}\n"
            f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n"
        )
