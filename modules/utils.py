# =============================================================
# modules/utils.py
# Utility / Helper Functions — CwX Edition
# =============================================================
# This module provides cross-platform helper functions used by
# the other modules: privilege checks, interface listing,
# banner display, and formatting utilities.
# =============================================================

import os
import sys
import platform
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# ── Force UTF-8 on Windows to prevent cp1252 encoding crashes ────
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass  # Fallback silently if reconfigure is unavailable

# force_terminal bypasses the legacy Windows console renderer
# that cannot handle Unicode block characters
console = Console(force_terminal=True)


# ----- CwX Branding Constants -----

CWX_BANNER = """
[bold cyan]
   CCCCCC  W       W  X     X
  C        W       W   X   X
  C        W   W   W    X X
  C        W  W W  W   X   X
   CCCCCC   WW   WW   X     X
[/bold cyan]
"""

SUBTITLE = (
    "[dim white]Advanced Packet Sniffer + ARP Detector[/dim white]  "
    "[bold yellow]│[/bold yellow]  "
    "[dim white]Defensive Network Monitor[/dim white]  "
    "[bold yellow]│[/bold yellow]  "
    "[dim cyan]v2.0 - 2026[/dim cyan]"
)

AUTHOR_LINE = (
    "[dim]Developed by [bold bright_white]Maniya Jay Maheshbhai[/bold bright_white]"
    " - [italic]24DCS050 | DEPSTAR[/italic][/dim]"
)


def print_banner():
    """Print the CwX branded ASCII art banner with subtitle and author."""
    from rich.align import Align

    console.print(Align.center(CWX_BANNER))
    console.print(Align.center(SUBTITLE))
    console.print(Align.center(AUTHOR_LINE))
    console.print()


def print_ethical_notice():
    """Print a short ethical / legal reminder at startup inside a Rich Panel."""
    notice_text = (
        "[bold yellow][!] ETHICAL NOTICE[/bold yellow]\n\n"
        "[white]Use this tool ONLY on networks you own or have explicit "
        "permission to monitor. Unauthorised packet sniffing is illegal "
        "in most jurisdictions.[/white]\n\n"
        "[dim]See ETHICAL_NOTICE.md for details.[/dim]"
    )
    console.print(
        Panel(
            notice_text,
            border_style="yellow",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )
    console.print()


# ------------------------------------------------------------------
# Privilege / Permission Checks
# ------------------------------------------------------------------

def check_privileges():
    """
    Check whether the current process has the elevated privileges
    required for raw-socket packet capture.

    Returns:
        bool: True if running with sufficient privileges.

    Behaviour per platform:
        - Linux : checks if effective UID == 0 (root)
        - Windows : attempts ctypes.windll to check admin status
    """
    current_os = platform.system()

    if current_os == "Linux":
        # On Linux, raw sockets require root (euid 0)
        return os.geteuid() == 0

    elif current_os == "Windows":
        # On Windows, we need Administrator privileges
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            # If the check itself fails, assume not admin
            return False

    else:
        # macOS / other UNIX — same root check as Linux
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def require_privileges():
    """
    Exit with a helpful message if the user lacks elevated privileges.
    Called before any live-capture operation.
    """
    if not check_privileges():
        console.print()
        if platform.system() == "Windows":
            console.print(
                Panel(
                    "[bold red][-] Insufficient privileges![/bold red]\n\n"
                    "[white]On Windows, right-click your terminal and select\n"
                    '"Run as Administrator", then try again.[/white]\n\n'
                    "[dim]Also make sure Npcap is installed:\n"
                    "https://npcap.com/#download[/dim]",
                    title="[bold red]Permission Error[/bold red]",
                    border_style="red",
                    box=box.HEAVY,
                    padding=(1, 2),
                )
            )
        else:
            console.print(
                Panel(
                    "[bold red][-] Insufficient privileges![/bold red]\n\n"
                    "[white]On Linux / macOS, run with sudo:[/white]\n"
                    "[dim]  sudo python main.py --live --interface eth0[/dim]",
                    title="[bold red]Permission Error[/bold red]",
                    border_style="red",
                    box=box.HEAVY,
                    padding=(1, 2),
                )
            )
        sys.exit(1)


# ------------------------------------------------------------------
# Network Interface Helpers
# ------------------------------------------------------------------

def list_interfaces():
    """
    List available network interfaces using Scapy's built-in
    utility.  Prints a formatted Rich Table to the terminal.
    """
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()

        table = Table(
            title="[bold bright_white]Available Network Interfaces[/bold bright_white]",
            box=box.ROUNDED,
            border_style="bright_cyan",
            header_style="bold bright_white on dark_blue",
            show_lines=True,
            padding=(0, 1),
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Interface Name", style="white")

        for idx, iface in enumerate(interfaces, start=1):
            table.add_row(str(idx), iface)

        console.print()
        console.print(table)
        console.print()
        return interfaces
    except Exception as exc:
        console.print(
            f"[bold red][-] Could not list interfaces: {exc}[/bold red]"
        )
        return []


def validate_interface(interface_name):
    """
    Verify that the requested interface exists on this machine.

    Args:
        interface_name (str): The name of the network interface.

    Returns:
        bool: True if the interface is found, False otherwise.
    """
    try:
        from scapy.arch import get_if_list
        available = get_if_list()
        if interface_name in available:
            return True
        # On Windows, Scapy may use a GUID-style name; also accept
        # partial / friendly matches.
        for iface in available:
            if interface_name.lower() in iface.lower():
                return True
        return False
    except Exception:
        return False


# ------------------------------------------------------------------
# Formatting Helpers
# ------------------------------------------------------------------

def timestamp():
    """Return a human-readable timestamp string for logs."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_mac(mac_address):
    """
    Normalise a MAC address to upper-case colon-separated format.

    Args:
        mac_address (str): Raw MAC address string.

    Returns:
        str: Normalised MAC address, e.g. "AA:BB:CC:DD:EE:FF".
    """
    return mac_address.upper().replace("-", ":")


def format_packet_summary(packet):
    """
    Build a one-line summary string for a captured packet.

    Args:
        packet: A Scapy packet object.

    Returns:
        str: Formatted summary line.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP

    ts = timestamp()
    summary_parts = [f"[{ts}]"]

    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "REQUEST" if arp.op == 1 else "REPLY"
        summary_parts.append(
            f"ARP {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})"
        )

    elif packet.haslayer(IP):
        ip = packet[IP]
        proto = "IP"
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            proto = "TCP"
            summary_parts.append(
                f"{proto}: {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} "
                f"[Flags: {tcp.flags}]"
            )
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            proto = "UDP"
            summary_parts.append(
                f"{proto}: {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
            )
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            summary_parts.append(
                f"{proto}: {ip.src} -> {ip.dst} (type={packet[ICMP].type})"
            )
        else:
            summary_parts.append(
                f"{proto}: {ip.src} -> {ip.dst} (proto={ip.proto})"
            )
    else:
        # Fallback to Scapy's built-in one-liner
        summary_parts.append(packet.summary())

    return " ".join(summary_parts)


def file_exists(path):
    """Check if a file exists at the given path."""
    return os.path.isfile(path)

# System console encoding configuration complete
