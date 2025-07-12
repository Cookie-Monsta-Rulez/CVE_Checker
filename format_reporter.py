import textwrap
from colorama import Fore, Style
import os
import requests
import re

def format_report(matches, rag_model):
    wrapper = textwrap.TextWrapper(width=80)
    report_lines = []
    for m in matches:
        report_lines.append(f"Host: {Fore.GREEN}{m['ip']}{Style.RESET_ALL}:{Fore.LIGHTGREEN_EX}{m['port']}{Style.RESET_ALL}")
        report_lines.append(f"Service: {Fore.LIGHTCYAN_EX}{m['product']} {Fore.LIGHTCYAN_EX}{m['version']}{Style.RESET_ALL}")
        report_lines.append(f"CVE: {Fore.YELLOW}{m['cve_id']}")
        report_lines.append(f"{Fore.WHITE}Description: {m['description']}")

        # Also add direct CVE->POC links if any
        direct_links = rag_model.cve_to_poc.get(m['cve_id'].upper(), [])
        if direct_links:
            report_lines.append("Known PoCs from ExploitDB:")
            for dl in direct_links:
                report_lines.append(f"  - {Fore.MAGENTA}{dl}{Style.RESET_ALL}")
                # Ensure output folder exists
                exploit_folder = "exploits"
                os.makedirs(exploit_folder, exist_ok=True)

                # Try to extract the EID from the URL
                match = re.search(r'/exploits/(\d+)', dl)
                if match:
                    eid = match.group(1)
                    download_url = f"https://www.exploit-db.com/download/{eid}"

                    try:
                        headers = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
                        }
                        response = requests.get(download_url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            filename = f"exploit_{m['cve_id'].upper()}.txt"
                            file_path = os.path.join(exploit_folder, filename)
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(response.text)
                            print(f"{Fore.GREEN}[+] Saved PoC to {Fore.LIGHTCYAN_EX}.\\{file_path}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}[!] Failed to download {download_url}: HTTP {response.status_code}")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error downloading {download_url}: {e}")
        else:
            report_lines.append(f"{Fore.RED}No known PoCs found in ExploitDB.{Style.RESET_ALL}")

        report_lines.append("-" * 80)
        report_lines.append("\n")
    return "\n".join(report_lines)