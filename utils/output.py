# Codes By Visionnn
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = r"""
 [bold cyan]
   _____                 _____           _            
  / ____|               |  __ \         | |           
 | |      __ _ _ __ ___ | |__) |__ _  __| | __ _ _ __ 
 | |     / _` | '_ ` _ \|  _  // _` |/ _` |/ _` | '__|
 | |____| (_| | | | | | | | \ \ (_| | (_| | (_| | |   
  \_____|\__,_|_| |_| |_|_|  \_\__,_|\__,_|\__,_|_|   
 [/bold cyan]
 [bold white]GitHub: https://github.com/vision-dev1[/bold white]
"""

def print_banner():
    console.print(Panel(Text.from_markup(BANNER), border_style="cyan"))

def display_results(results):
    table = Table(title="CamRadar Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("IP", style="dim")
    table.add_column("Device Type")
    table.add_column("Brand")
    table.add_column("Open Ports")
    table.add_column("Services")
    table.add_column("Risk Level")
    table.add_column("Notes")

    for res in results:
        risk_color = "red" if res['risk_level'] == "High" else "yellow" if res['risk_level'] == "Medium" else "green"
        table.add_row(
            res['ip'],
            res['device_type'],
            res['brand'],
            ", ".join(map(str, res['ports'])),
            ", ".join(res['services']),
            f"[{risk_color}]{res['risk_level']}[/{risk_color}]",
            res['notes']
        )
    
    console.print(table)

def print_summary(results):
    total = len(results)
    suspicious = sum(1 for r in results if r['risk_level'] in ["Medium", "High"])
    high_risk = sum(1 for r in results if r['risk_level'] == "High")
    
    summary_text = (
        f"\n[bold white]Scan Summary:[/bold white]\n"
        f"Total Devices Found: [bold blue]{total}[/bold blue]\n"
        f"Suspicious Devices: [bold yellow]{suspicious}[/bold yellow]\n"
        f"High Risk Devices: [bold red]{high_risk}[/bold red]\n"
    )
    console.print(Panel(Text.from_markup(summary_text), title="Summary", border_style="green"))

def export_json(results, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        console.print(f"[bold green]Report exported to {filename}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to export report: {e}[/bold red]")

def print_disclaimer():
    disclaimer = """
[bold red]ETHICAL USAGE DISCLAIMER[/bold red]
CamRadar is intended for authorized network security assessments only. 
Unauthorized scanning of networks you do not own or have explicit permission to test is illegal and unethical.
The authors are not responsible for any misuse of this tool.
"""
    console.print(Panel(Text.from_markup(disclaimer), border_style="red"))
