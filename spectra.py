#!/usr/bin/env python3
"""SPECTRA: authorized Nmap service inventory and NVD CVE correlation."""
import argparse
import datetime as dt
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_scan(xml_text):
    root = ET.fromstring(xml_text)
    results = []
    for host in root.findall("host"):
        address = host.find("address")
        hostname = host.find("hostnames/hostname")
        ip = address.get("addr", "") if address is not None else ""
        name = hostname.get("name", "") if hostname is not None else ""
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            svc = service.attrib if service is not None else {}
            cpes = [x.text for x in port.findall("service/cpe") if x.text]
            results.append({
                "host": ip, "hostname": name,
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "service": svc.get("name", ""),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "cpes": cpes,
                "cves": []
            })
    return results


def scan_host(host, timeout=180):
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap not found. Install Nmap and add it to PATH.")
    # No shell interpolation, OS detection, NSE scripts, or exploit execution.
    cmd = ["nmap", "-sT", "-sV", "--version-light", "-T2",
           "--max-rate", "20", "--max-retries", "1",
           "-Pn", "-oX", "-", "--", host]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Nmap scan failed")
    return proc.stdout


def get_cvss(item):
    metrics = item.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", "UNKNOWN")
    return None, "UNKNOWN"


def nvd_lookup(cpe, api_key=None, timeout=15):
    query = urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": 20})
    request = urllib.request.Request(
        NVD_URL + "?" + query,
        headers={"User-Agent": "SPECTRA-auditor/1.0",
                 **({"apiKey": api_key} if api_key else {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    findings = []
    for entry in payload.get("vulnerabilities", []):
        item = entry.get("cve", {})
        if item.get("vulnStatus") == "Rejected":
            continue
        descriptions = item.get("descriptions", [])
        desc = next((x.get("value", "") for x in descriptions
                     if x.get("lang") == "en"), "")
        score, severity = get_cvss(item)
        findings.append({
            "id": item.get("id", ""), "severity": severity,
            "score": score, "description": desc,
            "reference": "https://nvd.nist.gov/vuln/detail/" + item.get("id", "")
        })
    return findings


def enrich(services, api_key=None):
    cache = {}
    for service in services:
        for cpe in service["cpes"]:
            if cpe not in cache:
                try:
                    cache[cpe] = nvd_lookup(cpe, api_key=api_key)
                except (urllib.error.URLError, ValueError, TimeoutError) as exc:
                    print(f"[!] NVD lookup failed for {cpe}: {exc}", file=sys.stderr)
                    cache[cpe] = []
                time.sleep(0.7 if api_key else 6.1)
            existing = {c["id"] for c in service["cves"]}
            service["cves"].extend(c for c in cache[cpe] if c["id"] not in existing)


def render_html(report):
    esc = lambda value: html.escape(str(value))
    cards = []
    for service in report["services"]:
        title = f'{service["host"]}:{service["port"]}/{service["protocol"]}'
        product = " ".join(filter(None, [service["product"], service["version"]]))
        findings = []
        for cve in service["cves"]:
            severity = esc(cve["severity"])
            findings.append(
                '<div class="finding"><span class="pill">' + severity + '</span> '
                '<a href="' + esc(cve["reference"]) + '">' + esc(cve["id"]) + '</a>'
                '<p>' + esc(cve["description"][:350]) + '</p></div>')
        cards.append('<section class="card"><h2>' + esc(title) + '</h2><p>' +
                     esc(service["service"] + " · " + product) +
                     '</p><small>CPE: ' + esc(", ".join(service["cpes"]) or "not detected") +
                     '</small>' + ("".join(findings) if findings else
                     '<p class="muted">No CVE matches returned.</p>') + '</section>')
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SPECTRA · Security Report</title><style>
:root{color-scheme:dark;font-family:Inter,system-ui,Arial,sans-serif}
body{background:#0b1020;color:#e5e9f5;max-width:980px;margin:0 auto;padding:38px 20px}
header{padding:34px;border:1px solid #33365c;border-radius:20px;
background:linear-gradient(130deg,#1c1640,#111827)}
h1{font-size:40px;margin:0;color:#c7b7ff;letter-spacing:.12em}
h2{margin:0 0 8px;font-size:19px}
p{line-height:1.55}small,.muted{color:#9da8c0}
.grid{display:grid;gap:16px;margin-top:22px}
.card{padding:24px;background:#151c30;border:1px solid #2d3550;border-radius:16px}
.finding{border-top:1px solid #303a54;margin-top:15px;padding-top:15px}
.pill{background:#392b62;color:#dacbff;padding:5px 10px;border-radius:20px;font-size:12px}
a{color:#b9a6ff;text-decoration:none}a:hover{text-decoration:underline}
footer{color:#9da8c0;margin-top:24px;font-size:13px}</style></head><body>
<header><h1>◈ SPECTRA</h1><p>Service inventory &amp; CVE correlation</p>
<p>Generated: """ + esc(report["generated_at"]) + """</p></header>
<main class="grid">""" + "".join(cards) + """</main>
<footer>CVE matches are unverified leads, not proof of exploitation.
Review affected versions and configuration before remediation.</footer></body></html>"""


def main():
    parser = argparse.ArgumentParser(description="SPECTRA · authorized Nmap CVE auditor")
    parser.add_argument("target", nargs="?", help="Host you own or have permission to scan")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm permission to scan target")
    parser.add_argument("--xml", type=Path, help="Analyze an existing Nmap XML file")
    parser.add_argument("--output", type=Path, default=Path("reports"))
    args = parser.parse_args()
    if args.xml:
        xml = args.xml.read_text(encoding="utf-8")
    elif args.target and args.authorized:
        print("[*] Scanning authorized target...")
        xml = scan_host(args.target)
    else:
        parser.error("Provide --xml FILE or TARGET with --authorized")
    services = parse_scan(xml)
    print(f"[*] Discovered {len(services)} open services")
    enrich(services, api_key=os.getenv("NVD_API_KEY"))
    report = {
        "tool": "SPECTRA", "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": args.target or str(args.xml), "services": services,
        "note": "CVE correlation is not proof of exploitability."
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.output / "report.html").write_text(render_html(report), encoding="utf-8")
    print("[+] Reports written to", args.output.resolve())


if __name__ == "__main__":
    main()
