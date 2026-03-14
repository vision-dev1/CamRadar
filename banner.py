"""
banner.py - ASCII banner display for CamRadar.

Displays the CamRadar logo and author credit on startup.
"""

from colorama import Fore, Style


def display_banner():
    """Print the CamRadar ASCII art banner with author credit."""
    banner = rf"""
{Fore.CYAN}
   ____                 ____           _             
  / ___|__ _ _ __ ___  |  _ \ __ _  __| | __ _ _ __  
 | |   / _` | '_ ` _ \ | |_) / _` |/ _` |/ _` | '__| 
 | |__| (_| | | | | | ||  _ < (_| | (_| | (_| | |    
  \____\__,_|_| |_| |_||_| \_\__,_|\__,_|\__,_|_|    
{Style.RESET_ALL}
{Fore.GREEN}  CamRadar - Hidden Camera Detection Tool{Style.RESET_ALL}
{Fore.YELLOW}  by Vision --> github.com/vision-dev1{Style.RESET_ALL}
"""
    print(banner)
