# =============================================================
# modules/utils.py
# Utility / Helper Functions
# =============================================================
# This module provides cross-platform helper functions used by
# the other modules: privilege checks, interface listing,
# banner display, and formatting utilities.
# =============================================================

import os
import sys
import platform
from datetime import datetime

from colorama import Fore, Style

# Ensure stdout can handle UTF-8 on Windows (avoids cp1252 crashes)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass  # Fallback silently if reconfigure is unavailable


# ----- Constants -----
BANNER = """
+==============================================================+
|      Advanced Packet Sniffer + ARP Spoofing Detector         |
|      ------------------------------------------------        |
|      Defensive Network Monitoring Tool (Scapy)               |
|      For authorised networks only.                           |
+==============================================================+
"""


def print_banner():
    """Print the application banner in cyan."""
    print(Fore.CYAN + BANNER + Style.RESET_ALL)


def print_ethical_notice():
    """Print a short ethical / legal reminder at startup."""
    notice = (
        f"{Fore.YELLOW}[!] ETHICAL NOTICE:{Style.RESET_ALL} "
        "Use this tool ONLY on networks you own or have explicit permission "
        "to monitor. Unauthorised packet sniffing is illegal in most "
        "jurisdictions. See ETHICAL_NOTICE.md for details.\n"
    )
    print(notice)


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
        print(
            f"\n{Fore.RED}[✗] Insufficient privileges!{Style.RESET_ALL}\n"
        )
        if platform.system() == "Windows":
            print(
                "    On Windows, right-click your terminal and select\n"
                '    "Run as Administrator", then try again.\n'
                "    Also make sure Npcap is installed:\n"
                "    https://npcap.com/#download\n"
            )
        else:
            print(
                "    On Linux / macOS, run with sudo:\n"
                "      sudo python main.py --live --interface eth0\n"
            )
        sys.exit(1)


# ------------------------------------------------------------------
# Network Interface Helpers
# ------------------------------------------------------------------

def list_interfaces():
    """
    List available network interfaces using Scapy's built-in
    utility.  Prints a formatted table to the terminal.
    """
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        print(f"\n{Fore.GREEN}[+] Available network interfaces:{Style.RESET_ALL}")
        for idx, iface in enumerate(interfaces, start=1):
            print(f"    {idx}. {iface}")
        print()
        return interfaces
    except Exception as exc:
        print(
            f"{Fore.RED}[✗] Could not list interfaces: {exc}{Style.RESET_ALL}"
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
