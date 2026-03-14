"""
port_scan.py - Surveillance port scanner for CamRadar.

Checks target devices for open ports commonly used by IP cameras,
DVR systems, and streaming services.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style

from utils.logger import get_logger

logger = get_logger("camradar.scanner.port")


# ---------------------------------------------------------------------------
# Port lists
# ---------------------------------------------------------------------------

# Standard surveillance-related ports
CAMERA_PORTS: list[int] = [
    554,   # RTSP – IP camera streams
    80,    # HTTP – Web interface
    8080,  # HTTP alt – Alternate web interface
    8000,  # DVR systems
    8554,  # Media streaming
]

# Additional ports scanned in --deep mode
DEEP_PORTS: list[int] = [
    443,    # HTTPS
    8443,   # HTTPS alt
    9000,   # Common IoT port
    37777,  # Dahua DVR
    34567,  # Generic DVR
    5000,   # Synology / misc
    81,     # Alt HTTP
    8888,   # Alt web UI
    1935,   # RTMP streaming
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_port(ip: str, port: int, timeout: float = 1.0) -> int | None:
    """
    Check whether a single TCP port is open on *ip*.

    Args:
        ip: Target IP address.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        The port number if open, otherwise *None*.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
    except (socket.timeout, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_ports(ip: str, deep: bool = False, timeout: float = 1.0) -> list[int]:
    """
    Scan a target IP for surveillance-related open ports.

    Args:
        ip: Target IP address.
        deep: If *True*, include an extended list of IoT / DVR ports.
        timeout: Per-port connection timeout in seconds.

    Returns:
        A sorted list of open port numbers.
    """
    ports_to_scan = CAMERA_PORTS.copy()
    if deep:
        ports_to_scan.extend(DEEP_PORTS)
        logger.debug("Deep scan enabled – scanning %d ports on %s", len(ports_to_scan), ip)
    else:
        logger.debug("Standard scan – scanning %d ports on %s", len(ports_to_scan), ip)

    open_ports: list[int] = []

    # Use threads to speed up port scanning
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_port, ip, port, timeout): port
            for port in ports_to_scan
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort()

    if open_ports:
        logger.info(
            f"{Fore.GREEN}[+] {ip} has open port(s): "
            f"{', '.join(str(p) for p in open_ports)}{Style.RESET_ALL}"
        )
    else:
        logger.debug("No surveillance ports open on %s", ip)

    return open_ports
