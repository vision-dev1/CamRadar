"""
packet_sniffer.py - Network packet monitor for CamRadar.

Sniffs network traffic and alerts when RTSP or other streaming
protocols are detected. Runs until the user presses Ctrl+C.
"""

import sys

from colorama import Fore, Style

from utils.logger import get_logger

logger = get_logger("camradar.monitoring.sniffer")


# Ports to watch for streaming traffic
STREAMING_PORTS: set[int] = {554, 8554, 1935, 5004, 5005}


def _packet_callback(packet) -> None:
    """
    Callback invoked for each captured packet.

    Checks whether the packet is TCP/UDP traffic on a known streaming
    port and prints an alert if so.
    """
    from scapy.all import TCP, UDP, IP  # noqa: E402

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    sport = dport = 0
    proto = ""

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        proto = "TCP"
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        proto = "UDP"
    else:
        return

    # Check if either source or destination port matches a streaming port
    if sport in STREAMING_PORTS or dport in STREAMING_PORTS:
        port_hit = sport if sport in STREAMING_PORTS else dport
        msg = (
            f"{Fore.RED}[!] Streaming traffic detected  "
            f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport}  "
            f"(port {port_hit}){Style.RESET_ALL}"
        )
        print(msg)
        logger.warning(
            "Streaming traffic: %s %s:%d -> %s:%d (port %d)",
            proto, src_ip, sport, dst_ip, dport, port_hit,
        )

    # Check for RTSP signatures in raw payload
    if packet.haslayer(TCP) and packet[TCP].payload:
        try:
            payload = bytes(packet[TCP].payload)
            if b"RTSP" in payload or b"rtsp" in payload:
                msg = (
                    f"{Fore.RED}[!] RTSP payload detected  "
                    f"{src_ip} -> {dst_ip}{Style.RESET_ALL}"
                )
                print(msg)
                logger.warning("RTSP payload: %s -> %s", src_ip, dst_ip)
        except Exception:
            pass


def start_monitoring(interface: str | None = None, count: int = 0) -> None:
    """
    Start the packet sniffer.

    Captures packets on the specified network interface (or the default
    interface) and analyses them for streaming traffic.

    Args:
        interface: Network interface name (e.g. ``"eth0"``). If *None*,
                   scapy will use the default interface.
        count: Number of packets to capture (0 = unlimited, run until
               Ctrl+C).
    """
    try:
        from scapy.all import sniff  # noqa: E402
    except ImportError:
        print(
            f"{Fore.RED}[!] scapy is required for packet monitoring. "
            f"Install it with: pip install scapy{Style.RESET_ALL}"
        )
        logger.error("scapy not installed – cannot start packet monitor.")
        return

    print(f"\n{Fore.CYAN}[*] Starting packet monitor ...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}    Press Ctrl+C to stop.{Style.RESET_ALL}\n")
    logger.info("Packet monitor started (interface=%s, count=%d)", interface, count)

    try:
        sniff_kwargs: dict = {
            "prn": _packet_callback,
            "store": False,
            "count": count,
        }
        if interface:
            sniff_kwargs["iface"] = interface

        sniff(**sniff_kwargs)
    except PermissionError:
        print(
            f"{Fore.RED}[!] Insufficient privileges. "
            f"Run as administrator/root to capture packets.{Style.RESET_ALL}"
        )
        logger.error("PermissionError – packet monitoring requires elevated privileges.")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Packet monitor stopped by user.{Style.RESET_ALL}")
        logger.info("Packet monitor stopped by user.")
    except Exception as exc:
        print(f"{Fore.RED}[!] Packet monitoring error: {exc}{Style.RESET_ALL}")
        logger.error("Packet monitoring error: %s", exc)
