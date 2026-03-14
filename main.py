#!/usr/bin/env python3
"""
main.py - CLI entry point for CamRadar.

CamRadar is a Hidden Camera Detection Tool that scans local networks
to identify potential IP cameras or suspicious surveillance devices.

Usage:
    python main.py scan           Standard network scan
    python main.py scan --deep    Deep scan with extended port list
    python main.py monitor        Start packet monitoring
    python main.py help           Show help information

Author: Vision --> github.com/vision-dev1
"""

import argparse
import sys
import time

from colorama import init as colorama_init, Fore, Style

from banner import display_banner
from scanner.network_scan import discover_devices
from scanner.port_scan import scan_ports
from detection.camera_identifier import identify_device, print_device_report
from monitoring.packet_sniffer import start_monitoring
from utils.logger import get_logger

# Initialize colorama for cross-platform colored output
colorama_init(autoreset=False)

logger = get_logger("camradar")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(deep: bool = False, subnet: str | None = None) -> None:
    """
    Run a full network scan: discover devices → port scan → identify cameras.

    Args:
        deep: Enable extended port scanning.
        subnet: Target subnet override (auto-detected if *None*).
    """
    mode = "Deep" if deep else "Standard"
    print(f"\n{Fore.CYAN}[+] Starting {mode} Scan ...{Style.RESET_ALL}\n")
    logger.info("Starting %s scan (subnet=%s)", mode, subnet or "auto")

    start = time.time()

    # Step 1 – Discover devices
    devices = discover_devices(subnet)

    if not devices:
        print(f"\n{Fore.YELLOW}[!] No devices found. Exiting scan.{Style.RESET_ALL}")
        return

    # Step 2 – Port scan & identification
    cameras_found = 0
    for device in devices:
        ip = device["ip"]
        open_ports = scan_ports(ip, deep=deep)
        enriched = identify_device(device, open_ports)
        print_device_report(enriched)

        if enriched.get("is_camera"):
            cameras_found += 1

    elapsed = round(time.time() - start, 2)

    # Summary
    print(f"\n{Fore.CYAN}{'═' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Scan complete in {elapsed}s{Style.RESET_ALL}")
    print(f"    Total devices  : {len(devices)}")

    if cameras_found:
        print(
            f"    {Fore.RED}Suspicious devices : {cameras_found}{Style.RESET_ALL}"
        )
    else:
        print(
            f"    {Fore.GREEN}Suspicious devices : 0 — network looks clean{Style.RESET_ALL}"
        )

    print(f"{Fore.CYAN}{'═' * 50}{Style.RESET_ALL}\n")

    logger.info(
        "Scan finished in %ss – %d device(s), %d suspicious",
        elapsed, len(devices), cameras_found,
    )


def cmd_monitor(interface: str | None = None) -> None:
    """
    Start the packet monitoring mode.

    Args:
        interface: Network interface override.
    """
    print(f"\n{Fore.CYAN}[+] Entering Packet Monitoring Mode ...{Style.RESET_ALL}")
    start_monitoring(interface=interface)


def cmd_help() -> None:
    """Print an extended help / usage message."""
    help_text = f"""
{Fore.CYAN}CamRadar – Hidden Camera Detection Tool{Style.RESET_ALL}
{Fore.YELLOW}Usage:{Style.RESET_ALL}

  python main.py scan              Scan the local network for cameras
  python main.py scan --deep       Deep scan with extended port list
  python main.py scan --subnet X   Scan a specific subnet (e.g. 10.0.0.0/24)
  python main.py monitor           Monitor traffic for streaming activity
  python main.py monitor -i eth0   Monitor on a specific interface
  python main.py help              Show this help message

{Fore.YELLOW}Examples:{Style.RESET_ALL}

  python main.py scan
  python main.py scan --deep --subnet 192.168.0.0/24
  python main.py monitor

{Fore.YELLOW}Notes:{Style.RESET_ALL}

  • ARP scanning and packet monitoring may require elevated privileges
    (Administrator on Windows, root/sudo on Linux/macOS).
  • Logs are saved to logs/camradar.log
"""
    print(help_text)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for CamRadar."""
    parser = argparse.ArgumentParser(
        prog="camradar",
        description="CamRadar – Hidden Camera Detection Tool",
        add_help=True,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ---- scan ----
    scan_parser = subparsers.add_parser("scan", help="Scan the local network for cameras")
    scan_parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scan with extended port list",
    )
    scan_parser.add_argument(
        "--subnet",
        type=str,
        default=None,
        help="Target subnet (e.g. 192.168.1.0/24). Auto-detected if omitted.",
    )

    # ---- monitor ----
    monitor_parser = subparsers.add_parser(
        "monitor", help="Monitor network traffic for streaming protocols"
    )
    monitor_parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to monitor (default: auto)",
    )

    # ---- help ----
    subparsers.add_parser("help", help="Show detailed help information")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate command."""
    # Always show the banner
    display_banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(deep=args.deep, subnet=args.subnet)
    elif args.command == "monitor":
        cmd_monitor(interface=args.interface)
    elif args.command == "help":
        cmd_help()
    else:
        # No command supplied – show help
        cmd_help()


if __name__ == "__main__":
    main()
