# 🐍 ReconViper

> **Automated Bug Bounty Reconnaissance Pipeline** — Subfinder → HTTPX → Nmap → Nuclei → Markdown Report

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-ready-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
[![GitHub](https://img.shields.io/badge/GitHub-Portfolio-181717?logo=github)](https://github.com/your-username)

---

## 📌 Overview

ReconViper is a **Windows-native Python orchestration script** designed for bug bounty hunters and penetration testers. It chains four industry-standard recon tools into a single automated pipeline and produces a clean, professional Markdown report — all without requiring any external Python packages.

Built as a **Vocational Training (VT) capstone project**, it demonstrates:

- **Subprocess orchestration** — launching and managing external binaries
- **Pipeline architecture** — chaining tool outputs as stage inputs
- **Resilient error handling** — graceful degradation when tools are missing
- **Professional reporting** — auto-generated Markdown with findings summaries
- **Windows-first design** — proper PATH resolution for Go-based tooling on Windows

---

## 🏗️ Pipeline Architecture

```
┌─────────────┐     ┌─────────┐     ┌──────┐     ┌────────┐
│  Subfinder  │ ──▶ │  HTTPX  │ ──▶ │ Nmap │ ──▶ │ Nuclei │
│ (subdomains)│     │ (live)  │     │(ports)│     │ (vulns)│
└─────────────┘     └─────────┘     └──────┘     └────────┘
       │                  │              │              │
       ▼                  ▼              ▼              ▼
   subfinder_       httpx_         nmap_.txt     nuclei_
   domain.txt       domain.txt     domain.xml    domain.txt
                                                        │
                                                        ▼
                                               report_domain_
                                               timestamp.md
```

Each stage feeds its output as input to the next stage:

| Stage | Tool | Purpose | Input |
|-------|------|---------|-------|
| 1 | **Subfinder** | Enumerate subdomains | Target domain |
| 2 | **HTTPX** | Probe live hosts & detect tech | Subdomain list |
| 3 | **Nmap** | Port-scan live hosts (SYN, top 1000) | Live host URLs |
| 4 | **Nuclei** | Vulnerability scanning (low→critical) | Live host URLs |

---

## 🚀 Quick Start

### 1. Install the Recon Tools

ReconViper does **not** bundle tools — you install them separately. All are single Go binaries:

| Tool | Install (Windows) |
|------|-------------------|
| **Subfinder** | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **HTTPX** | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **Nmap** | Download from [nmap.org/download](https://nmap.org/download.html) (Windows installer) |
| **Nuclei** | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> 💡 Ensure each binary is on your `PATH`. ReconViper checks common locations (`%LOCALAPPDATA%`, `%PROGRAMFILES%`, `$HOME/go/bin`) automatically.

### 2. Run ReconViper

```batch
cd ReconViper
python reconviper.py example.com
```

**Output (real-time streaming):**
```
╔═══════════════════════════════════════════╗
║           ReconViper  v1.0.0              ║
║   Automated Bug Bounty Reconnaissance     ║
╚═══════════════════════════════════════════╝

  Reports → C:\Users\...\ReconViper\reports

########################################################
  # Domain 1/1
########################################################

════════════════════════════════════════════════════════
  TARGET : example.com
════════════════════════════════════════════════════════

▸ Subfinder — subdomain enumeration for example.com
  subfinder -d example.com -silent -o reports\subfinder_example.com.txt

▸ HTTPX — probing live hosts for example.com
  httpx -l reports\subfinder_example.com.txt -silent -o reports\httpx_example.com.txt ...
...
```

### 3. View the Report

After completion, open the generated report:

```batch
start reports\report_example_com_2026-07-29_22-14-00.md
```

Reports include:
- Summary table with finding counts per stage
- Full subdomain list
- Live hosts with status codes, titles, and detected technologies
- Open ports parsed from Nmap
- Vulnerabilities found by Nuclei

---

## 📖 Usage Guide

```batch
python reconviper.py --help
```

```
usage: reconviper.py [-h] [--list] [--skip {subfinder,httpx,nmap,nuclei} [{...}]]
                     [--timeout TIMEOUT] [--output OUTPUT]
                     target

ReconViper — Automated Bug Bounty Reconnaissance Pipeline

positional arguments:
  target                Target domain (e.g. example.com) OR path to a file of
                        domains (one per line) with --list

optional arguments:
  -h, --help            show this help message and exit
  --list, -l            Treat <target> as a file containing one domain per line
  --skip {subfinder,httpx,nmap,nuclei} [ {...}]
                        Skip one or more stages
  --timeout TIMEOUT     Per-command timeout in seconds (default: 1800)
  --output OUTPUT, -o OUTPUT
                        Custom output directory for reports (default: ./reports)
```

### Examples

```batch
:: Single domain
python reconviper.py example.com

:: Skip Nmap (faster, no port scan)
python reconviper.py example.com --skip nmap

:: Batch scan from a target list
python reconviper.py targets.txt --list

:: Custom output directory with extended timeout
python reconviper.py example.com --output C:\scans\example --timeout 3600

:: Skip all scanning stages, only run Subfinder
python reconviper.py example.com --skip httpx nmap nuclei
```

---

## 🧪 Sample Output

### Report Header

```markdown
# ReconViper Reconnaissance Report

**Target**      : `example.com`
**Generated**   : 2026-07-29 22:14:00
**Total Runtime**: 2 m 34 s
**Pipeline**    : Subfinder → HTTPX → Nmap → Nuclei

---

## 1. Summary

| Stage       | Tool       | Findings |
|-------------|------------|---------|
| Subdomains  | Subfinder  | 42 subdomains discovered |
| Live Hosts  | HTTPX      | 18 live hosts confirmed |
| Port Scan   | Nmap       | 23 open ports detected across 18 target(s) |
| Vuln Scan   | Nuclei     | 5 potential vulnerabilities found |

...
```

---

## 🛠️ Project Structure

```
ReconViper/
├── reconviper.py        # Main orchestration script
├── requirements.txt     # Dependencies (stdlib only)
├── .gitignore           # Ignores reports/ and Python caches
├── README.md            # This file
└── reports/             # Auto-generated scan reports (gitignored)
    ├── subfinder_example.com.txt
    ├── httpx_example.com.txt
    ├── nmap_example.com.txt
    ├── nuclei_example.com.txt
    └── report_example_com_2026-07-29_22-14-00.md
```

---

## ⚙️ Requirements

| Requirement | Minimum |
|------------|---------|
| OS | Windows 10/11 (also works on Linux/macOS with PATH adjustments) |
| Python | 3.9+ |
| External tools | Subfinder, HTTPX, Nmap, Nuclei (see install instructions above) |
| Python packages | None (stdlib only) |

---

## 🔧 Error Handling & Resilience

- **Missing tools** — ReconViper checks each tool at startup and skips stages gracefully with a clear message + download link
- **Empty stage output** — downstream stages handle empty input files without crashing
- **Timeout control** — each command has a configurable timeout (default 30 min) to prevent hanging
- **Keyboard interrupt** — `Ctrl+C` cleanly exits the pipeline
- **Per-domain isolation** — in batch mode, one domain failure does not affect others
- **UTF-8 resilience** — uses `errors="replace"` for all subprocess I/O to handle encoding edge cases

---

## 📚 Learning Outcomes (VT Portfolio)

This project was developed as part of a **Vocational Training program in Cybersecurity / Penetration Testing**. It demonstrates:

| Skill | Demonstrated By |
|-------|----------------|
| **Python programming** | Full CLI tool with argparse, subprocess, pathlib, type hints |
| **System integration** | Orchestrating external binaries with real-time output streaming |
| **Pipeline architecture** | Chaining stage outputs as subsequent stage inputs |
| **Error handling** | Graceful degradation, timeout management, interrupt handling |
| **Reporting** | Dynamic Markdown generation with findings aggregation |
| **Windows administration** | PATH resolution for Go-based security tooling |
| **Documentation** | Professional README with architecture diagrams and usage examples |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙌 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) — Subfinder, HTTPX, Nuclei
- [Nmap](https://nmap.org) — The gold standard of network scanning
- The bug bounty community for inspiration and tooling

---

<p align="center">
  <sub>Built with ❤️ for the bug bounty community</sub>
  <br>
  <sub>Vocational Training Project — Cybersecurity / Penetration Testing</sub>
</p>
