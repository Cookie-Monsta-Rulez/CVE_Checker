#!/usr/bin/python3

import requests
import gzip
import json
import xml.etree.ElementTree as ET
from packaging import version
import os
from typing import List
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import pandas as pd
import textwrap
from tqdm import tqdm
from yaspin import yaspin
import re
import pickle
from termcolor import colored
import pyfiglet
from colorama import Fore, Style
from nmap_parser import parse_nmap_services
from format_reporter import format_report
from nvd_feed import download_nvd_feed, parse_nvd_feed
from exploitdb import ExploitDBRAG, match_services_to_cves


NVD_2025_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.gz"
LOCAL_FEED_PATH = ".\\data\\nvdcve-1.1-2025.json.gz"
EXPLOITDB_PATH = ".\\data\\exploitdb_descriptions.json"
EXPLOITDB_INDEX_PATH = ".\\data\\exploitdb.index"
EXPLOITDB_META_PATH = ".\\data\\exploitdb.meta.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# Create the ExploitDB instance once (preferably at program start)
if not os.path.exists(".\\data"):
    os.makedirs(".\\data")
exploitdb_instance = ExploitDBRAG(force_download=False)
def main_menu():
    rag_model = None
    cves = None

    while True:
        banner = pyfiglet.figlet_format("CVE Checker")
        print(banner)
        print("1. Initialize the Database")
        print("2. Scan Nmap XML and report vulnerabilities")
        print("3. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
                try:
                    path = download_nvd_feed()
                    cves = parse_nvd_feed(path)
                except Exception as e:
                    print(colored(f"Error downloading/parsing NVD feed: {e}", 'red'))
                try:
                    rag_model = ExploitDBRAG()
                except Exception as e:
                    print(colored(f"Error loading ExploitDB: {e}", 'red'))

        elif choice == "2":
            if not cves or not rag_model:
                print(colored("Please download NVD feed and load ExploitDB first (options 1 and 2).", 'red'))
                continue

            xml_file = input("Enter path to Nmap XML scan file: ").strip()
            if not os.path.exists(xml_file):
                print(colored("File does not exist.", 'red'))
                continue

            services = parse_nmap_services(xml_file)
            if not services:
                print(colored("No services found in Nmap XML.", 'red'))
                continue

            matches = match_services_to_cves(services, cves)
            if not matches:
                print(colored("No vulnerabilities found matching detected services.", 'red'))
                continue

            report = format_report(matches, rag_model)
            print("\n=========== Vulnerability Report ===========\n")
            print(report)
            save = input("\nSave report to file? (y/N): ").strip().lower()
            if save == "y":
                out_file = input("Enter filename (e.g. report.txt): ").strip()
                reports_dir = os.path.join(os.getcwd(), "reports")
                os.makedirs(reports_dir, exist_ok=True)  # Create "reports" folder if it doesn't exist
                full_path = os.path.join(reports_dir, out_file)

                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(report)

                print(f"Report saved to {Fore.CYAN}{full_path}{Style.RESET_ALL}.")

        elif choice == "3":
            print("Exiting.")
            break
        else:
            print(colored("Invalid choice. Please try again.", 'red'))

if __name__ == "__main__":
    main_menu()
