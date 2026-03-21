import requests
from requests.exceptions import RequestException

class Fingerprinter:
    def __init__(self):
        self.brands = {
            "Hikvision": ["Hikvision", "App-webs", "DVR-Web-Management"],
            "Dahua": ["Dahua", "NET SURVEILLANCE", "DH-DVR"],
            "Axis": ["Axis Communications", "AXIS Video Server"],
            "TP-Link": ["TP-Link", "Tapo", "VIGI"]
        }

    def identify_service(self, port):
        if port == 554:
            return "RTSP"
        if port in [80, 443, 8080, 8888]:
            return "HTTP/HTTPS"
        if port == 8000:
            return "Hikvision SDK"
        if port == 37777:
            return "Dahua SDK"
        return "Unknown"

    def fingerprint_brand(self, ip, ports):
        """Attempts to identify brand using HTTP headers and page content."""
        for port in ports:
            if port in [80, 443, 8080]:
                protocol = "https" if port == 443 else "http"
                url = f"{protocol}://{ip}:{port}"
                try:
                    response = requests.get(url, timeout=2, verify=False)
                    server_header = response.headers.get('Server', '')
                    content = response.text
                    
                    for brand, keywords in self.brands.items():
                        if any(kw.lower() in server_header.lower() or kw.lower() in content.lower() for kw in keywords):
                            return brand
                except RequestException:
                    continue
        return "Generic/Unknown"

    def detect_onvif(self, ip, ports):
        """Simple check for ONVIF service endpoints."""
        # Standard ONVIF ports often 80, 8080, 8000
        # In a real tool, we would send a SOAP probe
        return "ONVIF" if 80 in ports or 8080 in ports or 8000 in ports else "Unknown"
