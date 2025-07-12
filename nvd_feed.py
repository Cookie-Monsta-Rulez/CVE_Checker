import os
import requests
import gzip
from tqdm import tqdm
import json
from nmap_parser import parse_nmap_services

NVD_2025_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.gz"
LOCAL_FEED_PATH = ".\\data\\nvdcve-1.1-2025.json.gz"
EXPLOITDB_PATH = ".\\data\\exploitdb_descriptions.json"
EXPLOITDB_INDEX_PATH = ".\\data\\exploitdb.index"
EXPLOITDB_META_PATH = ".\\data\\exploitdb.meta.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# ------------- DOWNLOAD NVD FEED -------------
def download_nvd_feed(url=NVD_2025_FEED_URL, path=LOCAL_FEED_PATH):
    if os.path.exists(path):
        print(f"[+] Feed already downloaded: {path}")
        return path
    print("[*] Downloading NVD 2025 feed...")
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open(path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
    print("[+] Download complete.")
    return path

# ------------- PARSE NVD JSON FEED -------------
def parse_nvd_feed(path=LOCAL_FEED_PATH):
    print("[*] Parsing NVD feed...")
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        data = json.load(f)

    cves = []
    for item in tqdm(data["CVE_Items"], desc="Parsing CVEs", unit="CVE"):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description_data = item["cve"]["description"]["description_data"]
        description = description_data[0]["value"] if description_data else ""
        configurations = item.get("configurations", {}).get("nodes", [])

        affected = []
        for node in configurations:
            for cpe_match in node.get("cpe_match", []):
                if cpe_match.get("vulnerable"):
                    cpe_uri = cpe_match.get("cpe23Uri") or cpe_match.get("criteria")
                    parts = cpe_uri.split(":")
                    if len(parts) >= 6:
                        vendor = parts[3]
                        product = parts[4]
                        ver = parts[5]

                        affected.append({
                            "vendor": vendor,
                            "product": product,
                            "version": ver,
                            "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                            "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                            "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                            "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                        })

        cves.append({
            "cve_id": cve_id,
            "description": description,
            "affected": affected,
        })

    print(f"[*] Parsed {len(cves)} CVEs from feed.")
    return cves

