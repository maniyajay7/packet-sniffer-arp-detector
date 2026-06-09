"""
╔══════════════════════════════════════════════════════════════════╗
║  CwX — Advanced Packet Sniffer + ARP Spoofing Detector          ║
║                                                                  ║
║  A terminal-based cybersecurity tool for defensive network       ║
║  monitoring: live packet sniffing, PCAP analysis, and real-time  ║
║  ARP spoofing detection using IP-to-MAC mapping validation.      ║
║                                                                  ║
║  Author  : Maniya Jay Maheshbhai                                 ║
║  ID      : 24DCS050                                              ║
║  Institute: Devang Patel Institute of Advance Technology         ║
║             and Research (DEPSTAR)                                ║
║                                                                  ║
║  This tool is for EDUCATIONAL and ETHICAL use only.              ║
║  Only use on networks you own or have explicit permission to     ║
║  monitor. See ETHICAL_NOTICE.md for details.                     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import argparse

# ── Force UTF-8 on Windows to prevent cp1252 encoding crashes ────
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.align import Align
from rich import box

from modules.utils import (
    CWX_BANNER,
    SUBTITLE,
    AUTHOR_LINE,
    print_banner,
    print_ethical_notice,
    list_interfaces,
)
from modules.sniffer import PacketSniffer
from modules.logger import log_info, log_error, get_log_filepath

# ── Configuration ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

# force_terminal bypasses the legacy Windows console renderer
# that cannot handle Unicode block characters
console = Console(force_terminal=True)


# ── Boot Sequence ────────────────────────────────────────────────

def display_boot_sequence() -> None:
    """Clear the terminal and display the CwX branded boot screen."""
    console.clear()
    console.print(Align.center(CWX_BANNER))
    console.print(Align.center(SUBTITLE))
    console.print(Align.center(AUTHOR_LINE))
    console.print()
    console.rule("[bold yellow]System Initialization[/bold yellow]", style="yellow")
    console.print()

    # Simulated boot checks for dramatic effect
    boot_steps = [
        ("Loading Scapy packet engine", 0.4),
        ("Initializing ARP spoofing detector", 0.3),
        ("Calibrating IP-to-MAC mapping table", 0.3),
        ("Preparing logging subsystem", 0.2),
        ("Scanning network interfaces", 0.4),
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold white]{task.description}[/bold white]"),
        BarColumn(bar_width=30, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for step_name, duration in boot_steps:
            task = progress.add_task(step_name, total=100)
            for _ in range(100):
                time.sleep(duration / 100)
                progress.advance(task)

    console.print()
    console.print(
        Align.center(
            "[bold bright_green][+] All systems operational[/bold bright_green]"
        )
    )
    console.print()

    # Print ethical notice
    print_ethical_notice()


# ── Interactive Menu ─────────────────────────────────────────────

def display_menu() -> None:
    """Display the main interactive command menu."""
    menu_text = (
        "[bold bright_white]1[/bold bright_white] [white]> Live Capture[/white]           "
        "[dim](sniff packets on a network interface)[/dim]\n"
        "[bold bright_white]2[/bold bright_white] [white]> Analyse PCAP[/white]           "
        "[dim](read and analyse a .pcap file)[/dim]\n"
        "[bold bright_white]3[/bold bright_white] [white]> Generate Sample PCAP[/white]   "
        "[dim](create test traffic for demo)[/dim]\n"
        "[bold bright_white]4[/bold bright_white] [white]> List Interfaces[/white]        "
        "[dim](show available network interfaces)[/dim]\n"
        "[bold bright_white]5[/bold bright_white] [white]> View Audit Logs[/white]        "
        "[dim](display recent log entries)[/dim]\n"
        "[bold bright_white]6[/bold bright_white] [white]> System Info[/white]             "
        "[dim](architecture & config overview)[/dim]\n"
        "[bold bright_white]0[/bold bright_white] [white]> Exit[/white]                   "
        "[dim](shutdown all systems)[/dim]"
    )

    console.print(
        Panel(
            menu_text,
            title="[bold bright_white]>> Command Center[/bold bright_white]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


# ── Option Handlers ──────────────────────────────────────────────

def handle_live_capture() -> None:
    """Prompt for interface and settings, then start live capture."""
    console.print()
    iface = console.input(
        "[bold cyan]  Enter interface name (e.g. eth0, Wi-Fi): [/bold cyan]"
    ).strip()

    if not iface:
        console.print("[bold red]  [-] No interface specified.[/bold red]\n")
        return

    # Ask for optional settings
    console.print("[dim]  Optional settings (press Enter to skip):[/dim]")

    count_str = console.input(
        "[bold cyan]  Packet count (0=unlimited): [/bold cyan]"
    ).strip()
    count = int(count_str) if count_str.isdigit() else 0

    timeout_str = console.input(
        "[bold cyan]  Timeout in seconds (blank=none): [/bold cyan]"
    ).strip()
    timeout = int(timeout_str) if timeout_str.isdigit() else None

    save_str = console.input(
        "[bold cyan]  Save to file (blank=no): [/bold cyan]"
    ).strip().strip("'\"")
    save_path = save_str if save_str else None

    verbose_str = console.input(
        "[bold cyan]  Verbose mode? (y/N): [/bold cyan]"
    ).strip().lower()
    verbose = verbose_str in ("y", "yes")

    console.print()
    console.rule(
        "[bold bright_white]Live Capture[/bold bright_white]",
        style="bright_green",
    )

    sniffer = PacketSniffer(
        interface=iface,
        verbose=verbose,
        save_path=save_path,
    )
    sniffer.start_live_capture(count=count, timeout=timeout)


def handle_pcap_analysis() -> None:
    """Prompt for PCAP file path and run analysis."""
    console.print()

    # Show available sample files if any
    if os.path.isdir(SAMPLES_DIR):
        samples = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(".pcap")]
        if samples:
            console.print("  [dim]Available sample files:[/dim]")
            for s in samples:
                console.print(f"    [dim cyan]• samples/{s}[/dim cyan]")
            console.print()

    pcap_path = console.input(
        "[bold cyan]  Enter PCAP file path: [/bold cyan]"
    ).strip().strip("'\"")

    if not pcap_path:
        console.print("[bold red]  [-] No file specified.[/bold red]\n")
        return

    verbose_str = console.input(
        "[bold cyan]  Verbose mode? (y/N): [/bold cyan]"
    ).strip().lower()
    verbose = verbose_str in ("y", "yes")

    save_str = console.input(
        "[bold cyan]  Save to file (blank=no): [/bold cyan]"
    ).strip().strip("'\"")
    save_path = save_str if save_str else None

    console.print()
    console.rule(
        f"[bold bright_white]PCAP Analysis: {os.path.basename(pcap_path)}[/bold bright_white]",
        style="bright_green",
    )

    sniffer = PacketSniffer(
        verbose=verbose,
        save_path=save_path,
    )
    sniffer.analyse_pcap(pcap_path)


def handle_generate_sample() -> None:
    """Run the sample PCAP generator script."""
    console.print()
    console.rule(
        "[bold bright_white]Generate Sample PCAP[/bold bright_white]",
        style="bright_green",
    )

    gen_script = os.path.join(BASE_DIR, "generate_sample_pcap.py")
    if not os.path.isfile(gen_script):
        console.print(
            "[bold red]  [-] generate_sample_pcap.py not found.[/bold red]\n"
        )
        return

    console.print(
        "  [bold bright_green][+][/bold bright_green] "
        "[white]Running sample PCAP generator...[/white]\n"
    )

    # Execute the generator script
    import subprocess
    result = subprocess.run(
        [sys.executable, gen_script],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
    )

    if result.stdout:
        for line in result.stdout.strip().split("\n"):
            console.print(f"  [dim]{line}[/dim]")

    if result.returncode == 0:
        console.print(
            "\n  [bold bright_green][+] Sample PCAP generated successfully![/bold bright_green]\n"
        )
    else:
        console.print(
            f"\n  [bold red][-] Generator failed (exit code {result.returncode})[/bold red]"
        )
        if result.stderr:
            for line in result.stderr.strip().split("\n"):
                console.print(f"  [dim red]{line}[/dim red]")
        console.print()


def view_audit_logs() -> None:
    """Display recent audit log entries in a formatted Rich Table."""
    log_path = get_log_filepath()
    if not os.path.exists(log_path):
        console.print("  [yellow]No audit logs found yet.[/yellow]\n")
        return

    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        console.print("  [yellow]Log file is empty.[/yellow]\n")
        return

    # Show last 20 entries
    recent = lines[-20:] if len(lines) > 20 else lines

    table = Table(
        title="[bold white]Recent Audit Log Entries[/bold white]",
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        header_style="bold white on dark_blue",
    )
    table.add_column("Timestamp", style="dim cyan", width=22)
    table.add_column("Level", justify="center", width=10)
    table.add_column("Message", style="dim", max_width=60)

    for line in recent:
        line = line.strip()
        if not line:
            continue
        # Parse the log format: "2026-06-09 14:30:00 | LEVEL    | message"
        parts = line.split(" | ", maxsplit=2)
        if len(parts) == 3:
            ts, level, msg = parts
            level = level.strip()
            if level == "CRITICAL":
                level_styled = f"[bold red]{level}[/bold red]"
            elif level == "ERROR":
                level_styled = f"[bold bright_red]{level}[/bold bright_red]"
            elif level == "WARNING":
                level_styled = f"[bold yellow]{level}[/bold yellow]"
            elif level == "INFO":
                level_styled = f"[dim green]{level}[/dim green]"
            else:
                level_styled = f"[dim]{level}[/dim]"

            table.add_row(ts[:19], level_styled, msg[:60])
        else:
            table.add_row("--", "--", line[:60])

    console.print()
    console.print(table)
    console.print(f"\n  [dim]Full log file: {log_path}[/dim]\n")


def display_system_info() -> None:
    """Show architecture and configuration overview."""
    info = (
        "[bold bright_white]Architecture[/bold bright_white]\n"
        "[dim]---------------------------------------------[/dim]\n"
        "  [cyan]Detection Layer :[/cyan]  ARP Spoofing Detection (IP→MAC changes)\n"
        "  [cyan]Packet Engine   :[/cyan]  Scapy (live capture + offline PCAP)\n"
        "  [cyan]Alert System    :[/cyan]  Gratuitous ARP + MAC Change Detection\n"
        "  [cyan]Monitoring      :[/cyan]  Real-time packet inspection\n"
        "  [cyan]Logging Format  :[/cyan]  Daily rotating log files\n"
        "\n"
        "[bold bright_white]Configuration[/bold bright_white]\n"
        "[dim]---------------------------------------------[/dim]\n"
        f"  [cyan]Samples Dir     :[/cyan]  {SAMPLES_DIR}\n"
        f"  [cyan]Log File        :[/cyan]  {get_log_filepath()}\n"
        "  [cyan]Supported Modes :[/cyan]  Live Capture, PCAP Analysis\n"
        "  [cyan]Platform        :[/cyan]  Linux + Windows (cross-platform)\n"
        "  [cyan]Dependencies    :[/cyan]  Scapy, Rich\n"
        "\n"
        "[bold bright_white]How Detection Works[/bold bright_white]\n"
        "[dim]---------------------------------------------[/dim]\n"
        "  The tool builds an IP→MAC mapping table from observed\n"
        "  ARP traffic. When a known IP address suddenly maps to a\n"
        "  different MAC address, an alert is raised — this is the\n"
        "  primary indicator of ARP spoofing / poisoning attacks.\n"
        "  Gratuitous ARP replies are also flagged as suspicious.\n"
    )

    console.print(
        Panel(
            info,
            title="[bold bright_white]<< System Architecture >>[/bold bright_white]",
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            padding=(1, 2),
        )
    )


# ── Argument Parser (backward-compatible CLI mode) ───────────────

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
            "CwX — Advanced Packet Sniffer + ARP Spoofing Detector\n"
            "A defensive network monitoring tool built with Scapy."
        ),
        epilog=(
            "ETHICAL NOTICE: Only use this tool on networks you own "
            "or have explicit permission to monitor.\n\n"
            "Run without arguments for interactive mode."
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


# ── Main Entry Point ─────────────────────────────────────────────

def main() -> None:
    """
    Main application entry point.

    Supports two modes:
        1. Interactive mode (default) — shows CwX boot sequence + menu
        2. CLI mode — when --live, --pcap, or --list-interfaces is used
    """
    parser = build_parser()
    args = parser.parse_args()

    # ── CLI Mode: if any mode flag is provided, run directly ─────
    if args.live or args.pcap or args.list_interfaces:
        # Show banner in CLI mode too
        print_banner()
        print_ethical_notice()

        if args.list_interfaces:
            list_interfaces()
            sys.exit(0)

        if args.pcap:
            log_info(f"Mode: PCAP file analysis ({args.pcap})")
            sniffer = PacketSniffer(
                verbose=args.verbose,
                save_path=args.save,
            )
            sniffer.analyse_pcap(args.pcap)
            sys.exit(0)

        if args.live:
            if not args.interface:
                log_error("Live capture requires --interface. Example:")
                console.print("  python main.py --live --interface eth0")
                console.print("  python main.py --live --interface Wi-Fi\n")
                console.print(
                    "  Use --list-interfaces to see available interfaces.\n"
                )
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

    # ── Interactive Mode (default) ───────────────────────────────
    try:
        # Phase 1: Boot sequence
        display_boot_sequence()

        # Phase 2: Interactive command loop
        while True:
            console.rule(style="dim")
            display_menu()
            choice = console.input(
                "\n[bold bright_cyan]  cwx>[/bold bright_cyan] "
            ).strip()

            if choice == "1":
                handle_live_capture()

            elif choice == "2":
                handle_pcap_analysis()

            elif choice == "3":
                handle_generate_sample()

            elif choice == "4":
                console.print()
                console.rule(
                    "[bold bright_white]Network Interfaces[/bold bright_white]",
                    style="bright_cyan",
                )
                list_interfaces()

            elif choice == "5":
                view_audit_logs()

            elif choice == "6":
                display_system_info()

            elif choice == "0":
                console.print(
                    "\n[bold bright_cyan]  Shutting down CwX systems...[/bold bright_cyan]"
                )
                log_info("CwX terminated by user.")
                console.print(
                    "[dim]  All processes terminated. Stay ethical.\n[/dim]"
                )
                sys.exit(0)

            else:
                console.print("  [red]Invalid option. Try again.[/red]")

    except KeyboardInterrupt:
        # ── Graceful Exit Override ────────────────────────────────
        # On Ctrl+C, print exactly this message (same as CwX Antivirus)
        print("\nhow did you know ?")
        sys.exit(0)


# Standard Python entry-point guard
if __name__ == "__main__":
    main()

# Final adjustments to project layout and guide instructions
