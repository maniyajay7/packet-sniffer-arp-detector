# =============================================================
# modules/arp_detector.py
# ARP Spoofing Detection Engine — CwX Edition
# =============================================================
# This module maintains an IP-to-MAC mapping table and inspects
# every ARP packet for signs of spoofing:
#
#   ► If an IP address was previously associated with MAC-A but
#     a new ARP packet maps it to MAC-B, an alert is raised.
#
#   ► Gratuitous ARP replies (unsolicited) are also flagged as
#     they are a common technique used in ARP poisoning.
#
# IMPORTANT — This module is purely DEFENSIVE.  It does not
# send any ARP packets; it only inspects incoming traffic.
# =============================================================

from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from modules.logger import log_alert, log_info, log_warning, log_debug
from modules.utils import format_mac, timestamp

# ── Console instance ─────────────────────────────────────────────
console = Console(force_terminal=True)


class ARPDetector:
    """
    ARP Spoofing Detection Engine.

    Maintains a live IP → MAC mapping table built from observed
    ARP traffic and alerts when a mapping changes (possible
    spoofing).

    Attributes:
        ip_mac_table (dict): Maps IP addresses to their last-seen
                             MAC address.
        alert_count  (int) : Running total of alerts raised.
        history      (list): List of dicts recording every
                             detected change.
    """

    def __init__(self):
        # Core mapping: { "192.168.1.1": "AA:BB:CC:DD:EE:FF" }
        self.ip_mac_table = {}

        # How many alerts have been raised so far
        self.alert_count = 0

        # Detailed history of detections
        # Each entry: { "time", "ip", "old_mac", "new_mac", "type" }
        self.history = []

    # ----------------------------------------------------------
    # Main inspection entry-point
    # ----------------------------------------------------------

    def inspect_arp_packet(self, packet):
        """
        Inspect a single ARP packet for spoofing indicators.

        This method is called by the sniffer for every ARP
        packet it captures (live or from a PCAP file).

        Args:
            packet: A Scapy packet that has an ARP layer.

        Returns:
            bool: True if an alert was raised, False otherwise.
        """
        from scapy.layers.l2 import ARP

        if not packet.haslayer(ARP):
            return False

        arp_layer = packet[ARP]

        # We are interested in ARP *replies* (op == 2) because
        # spoofing attacks inject fake replies.
        # However, we also track requests (op == 1) to build
        # our mapping table proactively.

        source_ip = arp_layer.psrc     # Sender protocol (IP) address
        source_mac = format_mac(arp_layer.hwsrc)  # Sender hardware (MAC) address

        alert_raised = False

        # --- Check 1: IP already in our table? ---
        if source_ip in self.ip_mac_table:
            known_mac = self.ip_mac_table[source_ip]

            if source_mac != known_mac:
                # MAC address changed for the same IP → possible spoof
                self._raise_alert(
                    alert_type="MAC_CHANGE",
                    ip=source_ip,
                    old_mac=known_mac,
                    new_mac=source_mac,
                )
                alert_raised = True

        # --- Check 2: Gratuitous ARP reply (sender IP == target IP) ---
        if arp_layer.op == 2 and arp_layer.psrc == arp_layer.pdst:
            log_warning(
                f"Gratuitous ARP detected from {source_ip} ({source_mac}). "
                "This could be legitimate (e.g. IP conflict detection) or "
                "a spoofing attempt."
            )

        # Update the table with the latest mapping
        self.ip_mac_table[source_ip] = source_mac
        log_debug(f"ARP table updated: {source_ip} -> {source_mac}")

        return alert_raised

    # ----------------------------------------------------------
    # Alert helpers
    # ----------------------------------------------------------

    def _raise_alert(self, alert_type, ip, old_mac, new_mac):
        """
        Record an alert and log it to the terminal + log file.

        Args:
            alert_type (str): Short label, e.g. "MAC_CHANGE".
            ip         (str): The IP address involved.
            old_mac    (str): Previously recorded MAC.
            new_mac    (str): Newly observed MAC.
        """
        self.alert_count += 1

        record = {
            "time": timestamp(),
            "ip": ip,
            "old_mac": old_mac,
            "new_mac": new_mac,
            "type": alert_type,
        }
        self.history.append(record)

        log_alert(
            f"POSSIBLE ARP SPOOFING DETECTED!\n"
            f"         IP Address : {ip}\n"
            f"         Old MAC    : {old_mac}\n"
            f"         New MAC    : {new_mac}\n"
            f"         Alert #    : {self.alert_count}"
        )

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------

    def print_arp_table(self):
        """
        Print the current IP-to-MAC mapping table to the terminal
        using a Rich Table with styled borders and headers.
        """
        table = Table(
            title="[bold bright_white]IP → MAC Mapping Table[/bold bright_white]",
            box=box.DOUBLE_EDGE,
            border_style="bright_cyan",
            header_style="bold bright_white on dark_blue",
            show_lines=True,
            padding=(0, 1),
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("IP Address", style="white", width=20)
        table.add_column("MAC Address", style="dim cyan", width=22)

        if not self.ip_mac_table:
            table.add_row(
                "--",
                "[dim yellow](empty — no ARP traffic observed yet)[/dim yellow]",
                "[dim]--[/dim]",
            )
        else:
            for idx, (ip_addr, mac_addr) in enumerate(
                sorted(self.ip_mac_table.items()), 1
            ):
                table.add_row(str(idx), ip_addr, mac_addr)

        console.print()
        console.print(table)
        console.print()

    def print_alert_summary(self):
        """
        Print a summary of all alerts raised during the session
        using a Rich Panel with red border.
        """
        if self.alert_count == 0:
            summary_text = (
                "[bold bright_green][+] No suspicious ARP activity detected.[/bold bright_green]\n\n"
                "[dim]All IP-to-MAC mappings remained consistent throughout the session.[/dim]"
            )
            border_color = "bright_green"
        else:
            lines = [
                f"[bold bright_red]Total alerts: {self.alert_count}[/bold bright_red]\n"
            ]
            for entry in self.history:
                lines.append(
                    f"  [dim]{entry['time']}[/dim]  "
                    f"[white]{entry['ip']}[/white]: "
                    f"[dim red]{entry['old_mac']}[/dim red] → "
                    f"[bold red]{entry['new_mac']}[/bold red]"
                )
            summary_text = "\n".join(lines)
            border_color = "bright_red"

        console.print(
            Panel(
                summary_text,
                title="[bold bright_white]:: ARP Spoofing Alert Summary[/bold bright_white]",
                border_style=border_color,
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            )
        )

    def get_stats(self):
        """
        Return a dict with quick statistics.

        Returns:
            dict: Keys = 'total_ips', 'alert_count', 'history'.
        """
        return {
            "total_ips": len(self.ip_mac_table),
            "alert_count": self.alert_count,
            "history": self.history,
        }

# ARP table mapping integrity check
