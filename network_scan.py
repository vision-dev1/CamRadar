"""
network_scan.py - Network device discovery for CamRadar.

Scans the local network to find connected devices using ARP requests
(via scapy) or python-nmap as a fallback.
"""

import socket
import struct
import sys

from colorama import Fore, Style

from utils.logger import get_logger

logger = get_logger("camradar.scanner.network")


# ---------------------------------------------------------------------------
# Helper – auto-detect local subnet
# ---------------------------------------------------------------------------

def _get_default_gateway_linux() -> str:
    """Read the default gateway from /proc/net/route (Linux only)."""
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == "00000000":  # default route
                    gateway_hex = parts[2]
                    gateway_ip = socket.inet_ntoa(
                        struct.pack("<L", int(gateway_hex, 16))
                    )
                    return gateway_ip
    except Exception:
        pass
    return ""


def get_local_subnet() -> str:
    """
    Attempt to determine the local subnet in CIDR notation (e.g. 192.168.1.0/24).

    Works cross-platform by connecting a UDP socket to a public IP
    (no data is actually sent) to discover the local IP address.

    Returns:
        A subnet string like ``"192.168.1.0/24"`` or ``"192.168.1.0/24"``
        as a sensible default.
    """
    try:
        # Connect a UDP socket to determine local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Assume a /24 subnet
        octets = local_ip.split(".")
        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        logger.debug("Auto-detected subnet: %s (local IP: %s)", subnet, local_ip)
        return subnet
    except Exception as exc:
        logger.warning("Could not auto-detect subnet: %s. Using 192.168.1.0/24", exc)
        return "192.168.1.0/24"


# ---------------------------------------------------------------------------
# Primary scan – scapy ARP
# ---------------------------------------------------------------------------

def _scan_with_scapy(subnet: str) -> list[dict]:
    """
    Perform an ARP scan using scapy.

    Args:
        subnet: Target subnet in CIDR notation.

    Returns:
        A list of dicts with ``ip`` and ``mac`` keys.
    """
    try:
        from scapy.all import ARP, Ether, srp  # noqa: E402

        logger.info(
            f"{Fore.CYAN}[*] Performing ARP scan on {subnet} using scapy ...{Style.RESET_ALL}"
        )

        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered, _ = srp(packet, timeout=3, verbose=False)

        devices: list[dict] = []
        for _, received in answered:
            devices.append(
                {
                    "ip": received.psrc,
                    "mac": received.hwsrc.upper(),
                }
            )

        logger.debug("Scapy ARP scan found %d device(s)", len(devices))
        return devices

    except ImportError:
        logger.warning("scapy is not installed – falling back to nmap.")
        return []
    except PermissionError:
        logger.warning(
            "Insufficient privileges for ARP scan – try running as admin/root. "
            "Falling back to nmap."
        )
        return []
    except Exception as exc:
        logger.warning("Scapy ARP scan failed (%s) – falling back to nmap.", exc)
        return []


# ---------------------------------------------------------------------------
# Fallback scan – python-nmap
# ---------------------------------------------------------------------------

def _scan_with_nmap(subnet: str) -> list[dict]:
    """
    Perform a host discovery scan using python-nmap.

    Args:
        subnet: Target subnet in CIDR notation.

    Returns:
        A list of dicts with ``ip`` and ``mac`` keys.
    """
    try:
        import nmap  # noqa: E402

        logger.info(
            f"{Fore.CYAN}[*] Performing host discovery on {subnet} using nmap ...{Style.RESET_ALL}"
        )

        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn")

        devices: list[dict] = []
        for host in nm.all_hosts():
            mac = ""
            if "mac" in nm[host]["addresses"]:
                mac = nm[host]["addresses"]["mac"].upper()
            devices.append({"ip": host, "mac": mac})

        logger.debug("Nmap scan found %d device(s)", len(devices))
        return devices

    except ImportError:
        logger.error(
            f"{Fore.RED}[!] python-nmap is not installed. "
            f"Install it with: pip install python-nmap{Style.RESET_ALL}"
        )
        return []
    except Exception as exc:
        logger.error("Nmap scan failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_devices(subnet: str | None = None) -> list[dict]:
    """
    Discover devices on the local network.

    Tries scapy first; falls back to python-nmap if scapy is unavailable
    or lacks permissions.

    Args:
        subnet: Target subnet (e.g. ``"192.168.1.0/24"``).
                 Auto-detected if *None*.

    Returns:
        A list of dicts, each containing ``ip`` and ``mac`` keys.
    """
    if subnet is None:
        subnet = get_local_subnet()

    devices = _scan_with_scapy(subnet)
    if not devices:
        devices = _scan_with_nmap(subnet)

    if devices:
        logger.info(
            f"{Fore.GREEN}[+] Discovered {len(devices)} device(s) on the network.{Style.RESET_ALL}"
        )
    else:
        logger.info(
            f"{Fore.YELLOW}[!] No devices discovered. "
            f"Ensure you are connected to a network and have proper permissions.{Style.RESET_ALL}"
        )

    return devices
