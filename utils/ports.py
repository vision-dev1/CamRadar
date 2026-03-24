# Codes By Visionnn
# CamRadar Common Ports

# RTSP: 554
# HTTP: 80, 443, 8080, 8888, 8000
# ONVIF/Proprietary: 37777 (Dahua), 8000 (Hikvision), 5000, 9000

SURVEILLANCE_PORTS = [80, 443, 554, 8000, 8080, 8888, 37777, 5000, 9000]

PORT_DESCRIPTIONS = {
    80: "HTTP (Web Management)",
    443: "HTTPS (Secure Web Management)",
    554: "RTSP (Real Time Streaming Protocol)",
    8000: "Hikvision SDK / Control Port",
    8080: "Alternative HTTP",
    8888: "Alternative HTTP / DVR Control",
    37777: "Dahua Web Service / SDK",
    5000: "UPnP / Device Discovery",
    9000: "Hikvision Config / Management"
}

def get_port_description(port):
    return PORT_DESCRIPTIONS.get(port, "Unknown Service")
