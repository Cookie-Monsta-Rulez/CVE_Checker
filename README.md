# CVE Checker
A python program to import an nmap XML scan and check the latest NVD and ExploitDB databases to see if there are any related CVEs. 

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/447b3c4f-8296-4ee3-b864-9d5962dbfc4f" />


This program initializes a database composed of the National Vulnerability Database and correlates ExploitDB entries to create an offline repository to check nmap scans against. Searchsploit did not seem to catch certain vulnerabilities, even when fully updated. Depending on if using a cached database or not, all vulnerabilities will be as up to date as possible allowing for timely identification of vulnerabilities. It will even download any relevant proof of concepts (POCs) and store them in an "exploits" folder. All generated vulnerability reports will be stored in "reports"

## Installation

Windows:
```
git clone --recursive https://github.com/Cookie-Monsta-Rulez/CVE_Checker.git
cd CVE_Checker
python -m virtualenv venv
source venv\scripts\activate
pip install -r requirements
python CVE_Checker.py
```

Linux: 
```
git clone --recursive https://github.com/Cookie-Monsta-Rulez/CVE_Checker.git
cd CVE_Checker
python -m virtualenv venv
source venv\scripts\activate
python CVE_Checker.py
```

## Usage

```
The program will initialize the database before executing (which may take a few minutes), but once done just select menu option 1 to ensure the database is ready and then option 2 to feed it scans!
```

## Support
If you have any suggestions or improvements please feel free to submit a pull request!

## Roadmap
Some features to be implemented: 
- Ingesting the scores for CVEs
- Allow for the pulling of directories for bulk import of scans
- Filtering on types of CVEs identified, such as RCEs 

## Authors and acknowledgment
This project was made by Cookie-Monsta-Rulez

## Contributions

## Acknowledgements: 




