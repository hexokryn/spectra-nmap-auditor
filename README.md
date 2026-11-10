<div align="center">

# ◈ SPECTRA
### Nmap-powered security posture auditor

**Discover services · Correlate CVEs · Prioritize remediation**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Nmap](https://img.shields.io/badge/Powered%20by-Nmap-4A90E2)
![License](https://img.shields.io/badge/License-MIT-purple)
![Security](https://img.shields.io/badge/Use-Authorized%20targets-2ea44f)

</div>

---

## Overview

SPECTRA is a lightweight Python security auditing tool. It runs a conservative Nmap service-version scan on an **authorized target**, correlates detected CPE identifiers with CVEs from the NVD database, and generates beautiful standalone HTML and JSON reports.

### Features

- **Service discovery:** TCP ports, service names, product versions, CPE identifiers
- **CVE enrichment:** NVD 2.0 API, CVSS scores, severity and descriptions
- **Reports:** Dark-themed responsive HTML plus machine-readable JSON
- **Safe by default:** No exploit execution, brute force or aggressive NSE scripts
- **Offline input:** Analyze existing Nmap XML files

## Installation

Requirements: Python 3.10+, [Nmap](https://nmap.org/download.html) installed and available on PATH.

```bash
git clone https://github.com/hexokryn/spectra-nmap-auditor.git
cd spectra-nmap-auditor
python -m pip install -r requirements.txt
```

No third-party Python dependencies are required.

## Usage

Scan a host you own or have explicit permission to test:

```bash
python spectra.py example.org --authorized --output reports
```

Analyze an existing Nmap XML file without running a new scan:

```bash
python spectra.py --xml scan.xml --output reports
```

Optional NVD API key to improve rate limits:

```bash
export NVD_API_KEY="your_api_key"
```

Windows PowerShell: `$env:NVD_API_KEY="your_api_key"`.

### Output

```text
reports/
├── report.html     # styled browser report
└── report.json     # structured results
```

### Workflow

```text
Authorized host / Nmap XML
          │
          ▼
   Service inventory
          │
          ▼
     CPE extraction
          │
          ▼
     NVD CVE lookup
          │
          ▼
  HTML + JSON reports
```

## Accuracy & safety

CPE-based CVE matches are **unverified leads**, not evidence of exploitability. Service banners can be misleading, CPE data may be missing, and a product may not be affected by every CVE returned for its CPE. Verify affected versions and configurations independently. NVD availability and API rate limits can affect results.

Only scan systems you own or are authorized to test. SPECTRA does not execute exploits or provide exploitation instructions.

## Project structure

```text
spectra.py           Python CLI, Nmap integration, NVD lookup, reports
requirements.txt     Dependency information
LICENSE              MIT license
.gitignore           Excludes local reports and caches
```

## License

MIT. See [LICENSE](LICENSE).
