"""
mac_vendor_lookup.py - MAC address vendor resolution for CamRadar.

Resolves MAC addresses to manufacturer names and checks whether the
vendor is a known surveillance camera manufacturer.
"""

from utils.logger import get_logger

logger = get_logger("camradar.detection.mac_vendor")


# ---------------------------------------------------------------------------
# Known surveillance camera vendors (case-insensitive matching)
# ---------------------------------------------------------------------------

SURVEILLANCE_VENDORS: list[str] = [
    "hikvision",
    "dahua",
    "tp-link",
    "xiaomi",
    "wyze",
    "axis",
    "foscam",
    "amcrest",
    "reolink",
    "annke",
    "swann",
    "lorex",
    "vivotek",
    "hanwha",
    "uniview",
    "ezviz",
    "imou",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_vendor(mac: str) -> str:
    """
    Resolve a MAC address to a vendor/manufacturer name.

    Uses the ``mac_vendor_lookup`` library. Returns ``"Unknown"`` if the
    lookup fails or the library is unavailable.

    Args:
        mac: MAC address string (e.g. ``"AA:BB:CC:DD:EE:FF"``).

    Returns:
        Vendor name as a string.
    """
    if not mac:
        return "Unknown"

    try:
        from mac_vendor_lookup import MacLookup  # noqa: E402

        vendor = MacLookup().lookup(mac)
        logger.debug("MAC %s -> Vendor: %s", mac, vendor)
        return vendor
    except ImportError:
        logger.warning("mac-vendor-lookup library not installed.")
        return "Unknown"
    except Exception:
        logger.debug("Vendor lookup failed for MAC %s", mac)
        return "Unknown"


def is_surveillance_vendor(vendor: str) -> bool:
    """
    Check whether *vendor* matches a known surveillance camera manufacturer.

    The comparison is case-insensitive and uses substring matching so that
    entries like ``"Hangzhou Hikvision Digital Technology"`` are caught.

    Args:
        vendor: Vendor/manufacturer name string.

    Returns:
        *True* if the vendor is a known surveillance camera manufacturer.
    """
    if not vendor or vendor == "Unknown":
        return False

    vendor_lower = vendor.lower()
    for sv in SURVEILLANCE_VENDORS:
        if sv in vendor_lower:
            logger.debug("Vendor '%s' matches surveillance vendor '%s'", vendor, sv)
            return True
    return False
