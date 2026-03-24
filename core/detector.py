# Codes By Visionnn
import requests

class RiskDetector:
    def __init__(self):
        pass

    def check_rtsp_unauth(self, ip):
        """Checks if RTSP stream is accessible without authentication."""
        # RTSP url usually: rtsp://ip:554/Streaming/Channels/101
        # This is a simplified check, in reality we would use an RTSP library
        return False # Placeholder - RTSP scanning is complex for a CLI tool without external libs

    def check_default_login(self, ip, ports):
        """Simple check for common login panel keywords."""
        for port in ports:
            if port in [80, 8080]:
                try:
                    url = f"http://{ip}:{port}"
                    response = requests.get(url, timeout=2)
                    if "login" in response.text.lower() or "admin" in response.text.lower():
                        return True
                except:
                    continue
        return False

    def assess_risk(self, ip, ports, brand, services):
        """Determines the risk level based on findings."""
        risk_level = "Low"
        notes = []

        if "RTSP" in services:
            risk_level = "Medium"
            notes.append("RTSP Service Exposed")
        
        if self.check_default_login(ip, ports):
            risk_level = "Medium"
            notes.append("Login Panel Found")

        if brand != "Generic/Unknown":
            notes.append(f"Identified as {brand}")

        if "Hikvision" in brand or "Dahua" in brand:
            notes.append("Check for CVE-2021-36260 / CVE-2017-3142")

        # Upgrade to High if multiple issues
        if len(notes) >= 2:
            risk_level = "High"

        if not notes:
            notes.append("No obvious risks detected")

        return risk_level, "; ".join(notes)
