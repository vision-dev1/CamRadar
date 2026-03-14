"""
camera_identifier.py - Camera identification engine for CamRadar.

Analyzes discovered devices and flags any that appear to be IP cameras
or surveillance devices based on open ports and vendor information.
"""
from colorama import Fore, Style

from detection.mac_vendor_lookup import lookup_vendor, is_surveillance_vendor
from utils.logger import get_logger

logger = get_logger("camradar.detection.camera")


# Ports that strongly indicate a camera / streaming device
STRONG_CAMERA_PORTS: set[int] = {554, 8554, 37777, 34567}

# Ports that may indicate a camera if combined with vendor match
WEAK_CAMERA_PORTS: set[int] = {80, 8080, 8000, 443, 8443, 9000, 81, 8888, 1935, 5000}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def identify_device(device: dict, open_ports: list[int]) -> dict:
    """
    Enrich a device dict with vendor info and a camera-likelihood flag.

    Args:
        device: Dict with ``ip`` and ``mac`` keys.
        open_ports: List of open port numbers found on the device.

    Returns:
        The same dict, enriched with:
        - ``vendor`` – manufacturer name
        - ``open_ports`` – the supplied open ports list
        - ``is_camera`` – *True* if the device looks like a surveillance device
        - ``reason`` – human-readable explanation for the flag
    """
    mac = device.get("mac", "")
    vendor = lookup_vendor(mac)
    surveillance_vendor = is_surveillance_vendor(vendor)

    is_camera = False
    reasons: list[str] = []

    # Check for strong camera ports
    strong_hits = STRONG_CAMERA_PORTS.intersection(open_ports)
    if strong_hits:
        is_camera = True
        reasons.append(f"Streaming port(s) open: {', '.join(str(p) for p in sorted(strong_hits))}")

    # Vendor match
    if surveillance_vendor:
        is_camera = True
        reasons.append(f"Vendor '{vendor}' is a known surveillance manufacturer")

    # Weak ports + vendor match
    if not is_camera and surveillance_vendor:
        weak_hits = WEAK_CAMERA_PORTS.intersection(open_ports)
        if weak_hits:
            is_camera = True
            reasons.append(
                f"Web port(s) open ({', '.join(str(p) for p in sorted(weak_hits))}) "
                f"and vendor matches surveillance list"
            )

    # Weak ports alone – still flag as potential
    if not is_camera:
        weak_hits = WEAK_CAMERA_PORTS.intersection(open_ports)
        if weak_hits and open_ports:
            # Only flag if at least one camera-relevant port is open
            camera_relevant = strong_hits or weak_hits
            if camera_relevant:
                is_camera = True
                reasons.append(
                    f"Open port(s) {', '.join(str(p) for p in sorted(open_ports))} "
                    f"may indicate a web-accessible camera"
                )

    device["vendor"] = vendor
    device["open_ports"] = open_ports
    device["is_camera"] = is_camera
    device["reason"] = "; ".join(reasons) if reasons else "No indicators found"

    return device


def print_device_report(device: dict) -> None:
    """
    Print a nicely formatted, colorized report for a single device.

    Args:
        device: Enriched device dict from :func:`identify_device`.
    """
    ip = device.get("ip", "N/A")
    mac = device.get("mac", "N/A")
    vendor = device.get("vendor", "Unknown")
    open_ports = device.get("open_ports", [])
    is_camera = device.get("is_camera", False)
    reason = device.get("reason", "")

    print(f"\n{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Device Discovered{Style.RESET_ALL}")
    print(f"    IP      : {ip}")
    print(f"    MAC     : {mac}")
    print(f"    Vendor  : {vendor}")

    if open_ports:
        ports_str = ", ".join(str(p) for p in open_ports)
        print(f"    Ports   : {ports_str}")

    if is_camera:
        print(
            f"\n    {Fore.RED}[!] Possible Surveillance Device Detected{Style.RESET_ALL}"
        )
        print(f"    {Fore.YELLOW}Reason: {reason}{Style.RESET_ALL}")
        logger.warning(
            "ALERT – Possible camera at %s (MAC: %s, Vendor: %s) – %s",
            ip, mac, vendor, reason,
        )
    else:
        print(f"    {Fore.GREEN}[✓] No camera indicators found{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")
