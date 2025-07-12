import csv
import os
import re
import requests

CSV_FILENAME = "files_exploits.csv"
CSV_URL = "https://raw.githubusercontent.com/offsoc/exploitdb/main/files_exploits.csv"

def extract_cves(text):
    return re.findall(r'CVE-\d{4}-\d{4,7}', text or "")

def download_csv(destination_dir):
    os.makedirs(destination_dir, exist_ok=True)
    dest_path = os.path.join(destination_dir, CSV_FILENAME)
    resp = requests.get(CSV_URL)
    if resp.status_code != 200:
        raise Exception("Failed to download ExploitDB CSV")
    with open(dest_path, "wb") as f:
        f.write(resp.content)
    return dest_path

def load_edb_cve_mapping(csv_path):
    edb_to_cves = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            edb_id = row["id"].strip()
            code_field = row.get("codes", "")
            cves = extract_cves(code_field)
            if cves:
                edb_to_cves[edb_id] = cves
    return edb_to_cves
