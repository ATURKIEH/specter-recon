# SPECTER-RECON

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![Category](https://img.shields.io/badge/Category-Offensive%20Security-red)
![Status](https://img.shields.io/badge/Status-Production--Ready-green)
![License](https://img.shields.io/badge/License-MIT-yellow)


<img width="531" height="223" alt="image" src="https://github.com/user-attachments/assets/e86bf2e3-d23b-47be-a1f5-9a34c200e1be" />

SPECTER-RECON is a modular reconnaissance automation framework designed to perform structured enumeration against authorized targets.

It integrates subdomain discovery, port scanning, service detection, web enumeration, crawling, SMB analysis, and structured reporting into a single automated pipeline.

---

## ⚡ Overview

SPECTER-RECON performs the following stages:

1. Target classification (Domain / IP)
2. Subdomain enumeration (crt.sh)
3. DNS resolution & IP aggregation
4. Fast threaded port scanning
5. Targeted Nmap service detection
6. Web service validation (curl)
7. Web enumeration (Nikto, FFUF)
8. Historical URL discovery (GAU)
9. Crawling (GoSpider)
10. SMB detection & anonymous enumeration
11. Automatic parsing & structured report generation

Each run generates:
- Structured raw outputs per tool
- Clean parsed results
- JSON summaries
- A final Markdown report
- Terminal summary output

---

## 📂 Output Structure

Each run generates a directory:


run/<target_timestamp>/
│
├── raw/
│ ├── crtsh/
│ ├── curl/
│ ├── ffuf/
│ ├── gau/
│ ├── gospider/
│ ├── nikto/
│ ├── nmap/
│ ├── smb/
│
├── report.md
├── target_summary.json
└── summary.json


- Raw outputs are stored separately from parsed results.
- Each tool has its own `raw/` and `clean/` directories.
- Final report is auto-generated.

---

## 🛠 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/specter-recon.git
cd specter-recon
```
## 📦 Requirements
Python

Python 3.10+

Install Python dependencies:
```bash
  pip install -r requirements.txt
```
  External Tools (Required)

Ensure the following tools are installed and available in PATH:

  1 - nmap
  
  2 - ffuf
  
  3 - nikto
  
  4 - gau
  
  5 - gospider
  
  6 - smbclient

Example (Debian/Kali):
```bash
sudo apt install nmap smbclient nikto
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/jaeles-project/gospider@latest
```
## 🚀 Usage
Single Target
```bash
python3 main.py \
  --target example.com \
  --profile deep \
  --threads 100 \
  --wordlist wordlists/DirBuster-2007_directory-list-2.3-medium.txt \
  --allow-private
```
Batch Mode
```bash
python3 main.py \
  --file targets.txt \
  --profile deep \
  --threads 100
```
## ⚙️ Arguments
Argument	Description
  -t, --target	Single domain or IP
  -f, --file	File containing targets (one per line)
  -o, --out	Output directory (default: ./run)
  -p, --profile	Scan profile (fast or deep)
  -T, --threads	Concurrency level (default: 50)
  -w, --wordlist	Wordlist path for FFUF
  --allow-private	Allow private IP ranges (lab/VPN use only)
## 🧠 Threading

The --threads argument affects:

  - Fast port scanning
  
  - FFUF
  
  - GoSpider

  Other modules run sequentially to maintain output stability.

## 📑 Wordlists

The repository currently includes 3 wordlists inside the wordlists/ directory.

Users may:

- Replace existing wordlists

- Add custom wordlists

- Use larger lists for deeper enumeration

- Simply pass your custom wordlist via:

    --wordlist path/to/your_wordlist.txt

# ⚠️ DISCLAIMER
This tool is intended only for:
 - Authorized Pen-testing
 - Lab environments
 - Educational purposes


