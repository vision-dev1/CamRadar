import socket
from scapy.all import ARP, Ether, srp
from utils.ports import SURVEILLANCE_PORTS

class NetworkScanner:
    def __init__(self, target):
        self.target = target

    def discover_hosts(self):
        """Discovers live hosts using ARP scan."""
        try:
            # ARP Scan
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target), timeout=2, verbose=False)
            hosts = []
            for sent, received in ans:
                hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
            return hosts
        except Exception as e:
            # Fallback to simple list if scapy fails (e.g. no admin)
            # In a real tool, we might try ping sweep here
            return []

    def scan_ports(self, ip, custom_ports=None, fast_mode=False):
        """Scans specified ports on a given IP."""
        open_ports = []
        ports_to_scan = custom_ports if custom_ports else SURVEILLANCE_PORTS
        
        # If fast mode, maybe limit ports or reduce timeout
        timeout = 0.5 if fast_mode else 1.0
        
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
