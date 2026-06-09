# =============================================================
# modules/sniffer.py
# Packet Sniffer Module — CwX Edition
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

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich import box

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

# ── Console instance ─────────────────────────────────────────────
console = Console(force_terminal=True)


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
                "interface list. Attempting capture anyway..."
            )
            console.print()
            list_interfaces()

        # Suppress Scapy's default verbose output
        conf.verb = 0

        log_info(
            f"Starting live capture on '{self.interface}' "
            f"(count={count}, timeout={timeout})..."
        )

        console.print(
            Panel(
                f"[bold bright_green]Live capture is now ACTIVE.[/bold bright_green]\n\n"
                f"[white]Interface : [bold]{self.interface}[/bold][/white]\n"
                f"[white]Count     : [bold]{count if count else 'unlimited'}[/bold][/white]\n"
                f"[white]Timeout   : [bold]{timeout if timeout else 'none'}[/bold][/white]\n\n"
                f"[dim]Press Ctrl+C to stop capturing.[/dim]",
                title="[bold][*] LIVE SNIFFER[/bold]",
                border_style="bright_green",
                box=box.HEAVY,
                padding=(1, 2),
            )
        )
        console.print()

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
                console.print(
                    Panel(
                        "[bold yellow][!] Npcap is not installed.[/bold yellow]\n\n"
                        "[white]Download it from:[/white]\n"
                        "[dim]https://npcap.com/#download[/dim]\n\n"
                        "[white]Install with 'WinPcap API-compatible Mode'.[/white]",
                        border_style="yellow",
                        box=box.ROUNDED,
                        padding=(1, 2),
                    )
                )
            sys.exit(1)
        except KeyboardInterrupt:
            # Graceful exit on Ctrl+C
            console.print(
                "\n  [bold yellow][!] Capture stopped by user.[/bold yellow]"
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
        console.print()

        # Process packets with a Rich progress bar
        with Progress(
            SpinnerColumn(spinner_name="dots", style="cyan"),
            TextColumn("[bold white]Analysing:[/bold white] {task.description}"),
            BarColumn(
                bar_width=40, complete_style="bright_green", finished_style="green"
            ),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                os.path.basename(pcap_path),
                total=len(packets),
            )

            for pkt in packets:
                self._process_packet(pkt)
                progress.advance(task)

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

        # Session statistics in a Rich Panel
        stats = self.arp_detector.get_stats()
        stats_text = (
            f"[bold white]Total packets processed :[/bold white]  "
            f"[bright_white]{self.packet_count}[/bright_white]\n"
            f"[bold white]ARP packets analysed    :[/bold white]  "
            f"[bright_white]{self.arp_packet_count}[/bright_white]\n"
            f"[bold white]Unique IPs in ARP table :[/bold white]  "
            f"[bright_white]{stats['total_ips']}[/bright_white]\n"
            f"[bold bright_red]Spoofing alerts raised  :[/bold bright_red]  "
            f"[bright_white]{stats['alert_count']}[/bright_white]\n"
            f"\n[dim]Audit log → {get_log_filepath()}[/dim]"
        )

        console.print(
            Panel(
                stats_text,
                title="[bold bright_white]:: Session Statistics[/bold bright_white]",
                border_style="bright_cyan",
                box=box.DOUBLE_EDGE,
                padding=(1, 3),
            )
        )
