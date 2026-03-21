import argparse
import sys
from core.scanner import NetworkScanner
from core.fingerprint import Fingerprinter
from core.detector import RiskDetector
from utils.output import print_banner, display_results, print_summary, export_json, print_disclaimer

def main():
    parser = argparse.ArgumentParser(description="CamRadar - IP Camera & Surveillance Network Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a network")
    scan_parser.add_argument("--target", default="192.168.1.0/24", help="Target subnet (default: 192.168.1.0/24)")
    scan_parser.add_argument("--fast", action="store_true", help="Quick scan mode")
    scan_parser.add_argument("--deep", action="store_true", help="More aggressive fingerprinting")
    scan_parser.add_argument("--ports", help="Custom ports to scan (comma-separated)")
    scan_parser.add_argument("--output", help="Export results to JSON file")
    scan_parser.add_argument("--stealth", action="store_true", help="Slow, stealthy scan")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        print_banner()
        print_disclaimer()
        
        custom_ports = None
        if args.ports:
            custom_ports = [int(p.strip()) for p in args.ports.split(",")]

        scanner = NetworkScanner(args.target)
        fingerprinter = Fingerprinter()
        detector = RiskDetector()

        print(f"[*] Starting scan on {args.target}...")
        hosts = scanner.discover_hosts()
        
        if not hosts:
            print("[!] No live hosts found via ARP scan. Ensure you have proper permissions (admin/sudo).")
            # In a real environment, we'd fall back to ping sweep here
            # For this demo, we'll simulate a find if target is local
            return

        print(f"[*] Found {len(hosts)} hosts. Enumerating services...")
        
        results = []
        for host in hosts:
            ip = host['ip']
            open_ports = scanner.scan_ports(ip, custom_ports, args.fast)
            
            if open_ports:
                brand = fingerprinter.fingerprint_brand(ip, open_ports)
                services = [fingerprinter.identify_service(p) for p in open_ports]
                risk_level, notes = detector.assess_risk(ip, open_ports, brand, services)
                
                results.append({
                    "ip": ip,
                    "device_type": "IP Camera/DVR" if any(p in [554, 37777, 8000] for p in open_ports) else "Unknown Device",
                    "brand": brand,
                    "ports": open_ports,
                    "services": list(set(services)),
                    "risk_level": risk_level,
                    "notes": notes
                })

        if results:
            display_results(results)
            print_summary(results)
            if args.output:
                export_json(results, args.output)
        else:
            print("[*] No surveillance devices identified.")

if __name__ == "__main__":
    main()
