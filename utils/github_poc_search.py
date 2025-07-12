import csv
import requests
import os
import re

# Define the path
folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'utils'))

file_path = os.path.join(folder_path, 'files_exploits.csv')


def extract_cves(code_string):
    # Extracts all CVE patterns from a string
    return re.findall(r'CVE-\d{4}-\d{4,7}', code_string)

# Make sure the folder exists
os.makedirs(folder_path, exist_ok=True)

url = "https://raw.githubusercontent.com/offsoc/exploitdb/main/files_exploits.csv"
response = requests.get(url)

with open("files_exploits.csv", "wb") as f:
    f.write(response.content)

print("CSV downloaded successfully!")

# Dictionary to store EDB-ID to CVE mapping
edb_to_cves = {}
with open(file_path, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        edb_id = row['id'].strip()
        code_field = row.get('codes', '')
        cve_list = extract_cves(code_field)
        if cve_list:
            edb_to_cves[edb_id] = cve_list


# Example usage
print(edb_to_cves.get('52134'))  # Replace with actual EDB-ID
