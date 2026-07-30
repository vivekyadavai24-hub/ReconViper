#!/usr/bin/env python3
"""
ReconViper — Automated Bug Bounty Reconnaissance Pipeline
         __                ___________       
   _____/ /___  ____  ____/ / ____/ / | ____ 
  / ___/ / __ \/ __ \/ __  / /   / /| |/ __ \
 / /__/ / /_/ / / / / /_/ / /___/ ___ / /_/ /
 \___/_/\____/_/ /_/\__,_/\____/_/ |_/ .___/ 
                                    /_/       

Windows-native orchestration script that chains industry-standard
recon tools (Subfinder → HTTPX → Nmap → Nuclei) and produces a
professional Markdown report.

Author  : Vivek Yadav / https://github.com/vivekyadavai24-hub
License : MIT
"""

import os
import sys
import json
import subprocess
import datetime
import re
import shutil
import argparse
import textwrap
from pathlib import Path
from typing import List, Optional, Dict, Any

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = SCRIPT_DIR / "reports"
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

TOOL_NAMES = {
    "subfinder": "Subfinder",
    "httpx":      "HTTPX",
    "nmap":       "Nmap",
    "nuclei":     "Nuclei",
}

# ──────────────────────────────────────────────────────────────────────
# Utility helpers
# ──────────────────────────────────────────────────────────────────────

def green(msg: str) -> str:
    return f"\033[92m{msg}\033[0m"

def yellow(msg: str) -> str:
    return f"\033[93m{msg}\033[0m"

def red(msg: str) -> str:
    return f"\033[91m{msg}\033[0m"

def cyan(msg: str) -> str:
    return f"\033[96m{msg}\033[0m"

def banner() -> None:
    print(cyan(textwrap.dedent("""\
        ╔═══════════════════════════════════════════╗
        ║           ReconViper  v1.0.0              ║
        ║   Automated Bug Bounty Reconnaissance     ║
        ╚═══════════════════════════════════════════╝
    """)))

def check_tool(name: str) -> Optional[Path]:
    """Return the absolute path of *name* if found in PATH, else None."""
    resolved = shutil.which(name)
    if resolved:
        return Path(resolved)
    # Also check common Windows install locations as fallback
    common_dirs = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs",
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")),
        Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")),
        Path.home() / "go" / "bin",
        Path.home() / "AppData" / "Local" / "go" / "bin",
    ]
    for d in common_dirs:
        candidate = d / f"{name}.exe"
        if candidate.exists():
            return candidate
        candidate = d / name
        if candidate.exists():
            return candidate
    return None

def run_cmd(cmd: List[str], desc: str, timeout: int = 1800) -> subprocess.CompletedProcess:
    """
    Execute a shell command, stream output in real-time, and return the
    CompletedProcess object.  Raises TimeoutExpired on timeout.
    """
    print(f"\n{cyan('▸')} {desc}")
    print(f"  {' '.join(cmd)}\n")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        stdout_lines: List[str] = []
        for line in proc.stdout:                      # type: ignore[union-attr]
            print(line, end="")
            stdout_lines.append(line)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    result = subprocess.CompletedProcess(cmd, proc.returncode, "".join(stdout_lines))
    return result


def save_output(content: str, filename: str) -> Path:
    """Write *content* to reports/<filename> and return the path."""
    filepath = REPORTS_DIR / filename
    filepath.write_text(content, encoding="utf-8")
    return filepath


def read_file_safe(path: Path) -> str:
    """Read a text file, returning empty string on error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


# ──────────────────────────────────────────────────────────────────────
# Pipeline stages
# ──────────────────────────────────────────────────────────────────────

def stage_subfinder(domain: str, subfinder_path: Path, out_dir: Path) -> Path:
    """Enumerate subdomains with Subfinder."""
    out = out_dir / f"subfinder_{domain}.txt"
    cmd = [
        str(subfinder_path),
        "-d", domain,
        "-silent",
        "-o", str(out),
    ]
    run_cmd(cmd, f"Subfinder — subdomain enumeration for {domain}")
    if not out.exists():
        out.write_text("")
    return out


def stage_httpx(domain: str, subdomains_file: Path, httpx_path: Path, out_dir: Path) -> Path:
    """Probe live hosts with HTTPX."""
    out = out_dir / f"httpx_{domain}.txt"
    cmd = [
        str(httpx_path),
        "-l", str(subdomains_file),
        "-silent",
        "-o", str(out),
        "-title", "-status-code", "-tech-detect", "-follow-redirects",
    ]
    run_cmd(cmd, f"HTTPX — probing live hosts for {domain}")
    if not out.exists():
        out.write_text("")
    return out


def stage_nmap(domain: str, live_hosts_file: Path, out_dir: Path) -> Path:
    """Port-scan live hosts with Nmap (fast SYN scan on top ports)."""
    out_xml = out_dir / f"nmap_{domain}.xml"
    out_txt = out_dir / f"nmap_{domain}.txt"
    # Build list of targets from httpx output (first column = URL)
    targets = []
    raw = read_file_safe(live_hosts_file)
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # HTTPX outputs scheme://host:port; extract hostname/IP
        m = re.match(r"https?://([^:/]+)", line)
        if m:
            targets.append(m.group(1))
    if not targets:
        print(yellow("  ⚠  No live hosts to scan — skipping Nmap."))
        out_txt.write_text("No live hosts found — Nmap scan skipped.\n")
        return out_txt

    targets_str = " ".join(sorted(set(targets)))
    cmd = [
        str(shutil.which("nmap") or "nmap"),
        "-sS", "-T4", "--top-ports", "1000",
        "-oX", str(out_xml),
        "-oN", str(out_txt),
        "--append-output",
    ] + targets.split()
    run_cmd(cmd, f"Nmap — port scanning {len(set(targets))} target(s) for {domain}",
            timeout=3600)
    if not out_txt.exists():
        out_txt.write_text("Nmap scan produced no output.\n")
    return out_txt


def stage_nuclei(domain: str, live_hosts_file: Path, nuclei_path: Path, out_dir: Path) -> Path:
    """Run Nuclei vulnerability scanner against live hosts."""
    out = out_dir / f"nuclei_{domain}.txt"
    cmd = [
        str(nuclei_path),
        "-l", str(live_hosts_file),
        "-silent",
        "-o", str(out),
        "-severity", "low,medium,high,critical",
        "-etags", "info",
    ]
    run_cmd(cmd, f"Nuclei — vulnerability scanning for {domain} (low→critical)")
    if not out.exists():
        out.write_text("")
    return out


# ──────────────────────────────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────────────────────────────

def _count_lines(path: Path) -> int:
    """Count non-empty lines in a file."""
    return len([l for l in read_file_safe(path).strip().splitlines() if l.strip()])


def _extract_nmap_summary(nmap_text: str) -> List[str]:
    """Pull interesting port lines from Nmap output."""
    lines = []
    capture = False
    for line in nmap_text.splitlines():
        if re.search(r"PORT\s+STATE\s+SERVICE", line):
            capture = True
            continue
        if capture:
            if re.match(r"^\d+/", line):
                lines.append(line.strip())
            elif not line.strip():
                break
    return lines


def generate_report(domain: str, out_dir: Path, results: Dict[str, Any]) -> str:
    """Assemble and return the full Markdown report string; write to disk."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    runtime = results.get("runtime_seconds", 0)
    minutes, secs = divmod(int(runtime), 60)

    sub_path   = results.get("subfinder", Path())
    httpx_path = results.get("httpx", Path())
    nmap_path  = results.get("nmap", Path())
    nuclei_path = results.get("nuclei", Path())

    sub_count   = _count_lines(sub_path)
    live_count  = _count_lines(httpx_path)
    vuln_count  = _count_lines(nuclei_path)

    nmap_raw   = read_file_safe(nmap_path)
    nmap_ports = _extract_nmap_summary(nmap_raw)

    # ── Build report ──────────────────────────────────────────────
    report = f"""# ReconViper Reconnaissance Report

**Target**      : `{domain}`
**Generated**   : {now}
**Total Runtime**: {minutes} m {secs} s
**Pipeline**    : Subfinder → HTTPX → Nmap → Nuclei

---

## 1. Summary

| Stage       | Tool       | Findings |
|-------------|------------|---------|
| Subdomains  | Subfinder  | {sub_count} subdomains discovered |
| Live Hosts  | HTTPX      | {live_count} live hosts confirmed |
| Port Scan   | Nmap       | {len(nmap_ports)} open ports detected across {results.get('nmap_targets', 0)} target(s) |
| Vuln Scan   | Nuclei     | {vuln_count} potential vulnerabilities found |

---

## 2. Subdomain Enumeration

```
[Subfinder — {sub_path.name}]
"""

    sub_content = read_file_safe(sub_path).strip()
    report += (sub_content if sub_content else "*No subdomains discovered.*")
    report += "\n```\n\n"

    # ── Live hosts ────────────────────────────────────────────────
    report += "## 3. Live Hosts (HTTPX)\n\n```\n"
    httpx_content = read_file_safe(httpx_path).strip()
    report += (httpx_content if httpx_content else "*No live hosts found.*")
    report += "\n```\n\n"

    # ── Open ports ────────────────────────────────────────────────
    report += "## 4. Open Ports (Nmap)\n\n```\n"
    if nmap_ports:
        report += "\n".join(nmap_ports)
    else:
        # Try raw output
        nmap_trimmed = nmap_raw.strip()
        report += nmap_trimmed if nmap_trimmed else "*Nmap scan produced no port data.*"
    report += "\n```\n\n"

    # ── Vulnerabilities ───────────────────────────────────────────
    report += "## 5. Vulnerabilities (Nuclei)\n\n```\n"
    nuclei_content = read_file_safe(nuclei_path).strip()
    report += (nuclei_content if nuclei_content else "*No vulnerabilities detected by Nuclei.*")
    report += "\n```\n\n"

    # ── Raw output files ──────────────────────────────────────────
    report += """---
## 6. Raw Output Files

All stage outputs are saved in the `reports/` directory:
"""

    for stage, fpath in [
        ("Subfinder", sub_path),
        ("HTTPX",     httpx_path),
        ("Nmap",      nmap_path),
        ("Nuclei",    nuclei_path),
    ]:
        if fpath and fpath.exists():
            report += f"- `{fpath.name}` — {stage}\n"
        else:
            report += f"- *(no file)* — {stage}\n"

    report += f"""
---

*Report auto-generated by **ReconViper** at {now}.*
"""

    # ── Write to disk ─────────────────────────────────────────────
    report_filename = f"report_{domain}_{TIMESTAMP}.md"
    report_path = REPORTS_DIR / report_filename
    report_path.write_text(report, encoding="utf-8")
    print(f"\n{green('✔')} Report saved → {report_path}")
    return report


# ──────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconviper",
        description="ReconViper — Automated Bug Bounty Reconnaissance Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python reconviper.py example.com
              python reconviper.py example.com --skip nmap --timeout 600
              python reconviper.py target-list.txt --list
        """),
    )
    parser.add_argument(
        "target",
        help="Target domain (e.g. example.com) OR path to a file of domains (one per line) with --list",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="Treat <target> as a file containing one domain per line",
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        default=[],
        choices=["subfinder", "httpx", "nmap", "nuclei"],
        help="Skip one or more stages",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Per-command timeout in seconds (default: 1800)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Custom output directory for reports (default: ./reports)",
    )
    return parser.parse_args()


def process_domain(domain: str, args: argparse.Namespace, out_dir: Path) -> float:
    """Run the full pipeline for a single domain. Returns elapsed seconds."""
    start = datetime.datetime.now()
    domain = domain.strip().lower()
    print(cyan(f"\n{'═' * 56}"))
    print(cyan(f"  TARGET : {domain}"))
    print(cyan(f"{'═' * 56}\n"))

    # ── Resolve tool paths ────────────────────────────────────────
    tools: Dict[str, Optional[Path]] = {}
    for name in TOOL_NAMES:
        tools[name] = check_tool(name)
        if name not in args.skip and tools[name] is None:
            print(red(f"  ✘  {TOOL_NAMES[name]} not found in PATH. Install it or use --skip {name}"))
            print(yellow(f"     Download: https://github.com/projectdiscovery/{name}"))

    # ── Pipeline execution ────────────────────────────────────────
    results: Dict[str, Any] = {}

    # Stage 1: Subfinder
    if "subfinder" not in args.skip and tools["subfinder"]:
        results["subfinder"] = stage_subfinder(
            domain, tools["subfinder"], out_dir
        )
    else:
        print(yellow("  ⏭  Skipping Subfinder (--skip or not available)"))
        results["subfinder"] = out_dir / f"subfinder_{domain}.txt"

    # Stage 2: HTTPX (requires subfinder output)
    httpx_input = results.get("subfinder", Path())
    if "httpx" not in args.skip and tools["httpx"] and httpx_input.exists():
        results["httpx"] = stage_httpx(
            domain, httpx_input, tools["httpx"], out_dir
        )
    else:
        print(yellow("  ⏭  Skipping HTTPX"))
        results["httpx"] = out_dir / f"httpx_{domain}.txt"

    # Stage 3: Nmap (requires httpx output)
    nmap_input = results.get("httpx", Path())
    if "nmap" not in args.skip and tools["nmap"] and nmap_input.exists():
        # Count targets for the report
        raw = read_file_safe(nmap_input)
        targets = set()
        for line in raw.strip().splitlines():
            m = re.match(r"https?://([^:/]+)", line.strip())
            if m:
                targets.add(m.group(1))
        results["nmap_targets"] = len(targets)
        results["nmap"] = stage_nmap(domain, nmap_input, out_dir)
    else:
        print(yellow("  ⏭  Skipping Nmap"))
        results["nmap"] = out_dir / f"nmap_{domain}.txt"
        results["nmap_targets"] = 0

    # Stage 4: Nuclei (requires httpx output)
    nuclei_input = results.get("httpx", Path())
    if "nuclei" not in args.skip and tools["nuclei"] and nuclei_input.exists():
        results["nuclei"] = stage_nuclei(
            domain, nuclei_input, tools["nuclei"], out_dir
        )
    else:
        print(yellow("  ⏭  Skipping Nuclei"))
        results["nuclei"] = out_dir / f"nuclei_{domain}.txt"

    # ── Report ─────────────────────────────────────────────────────
    elapsed = (datetime.datetime.now() - start).total_seconds()
    results["runtime_seconds"] = elapsed
    generate_report(domain, out_dir, results)

    return elapsed


def main() -> None:
    banner()

    args = parse_args()

    # Output directory
    global REPORTS_DIR
    if args.output:
        REPORTS_DIR = Path(args.output).resolve()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  Reports → {REPORTS_DIR}\n")

    global TIMESTAMP
    TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # ── Resolve targets ───────────────────────────────────────────
    if args.list:
        target_file = Path(args.target)
        if not target_file.exists():
            print(red(f"  ✘  Target list file not found: {target_file}"))
            sys.exit(1)
        domains = [
            l.strip() for l in target_file.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        if not domains:
            print(red("  ✘  Target list is empty."))
            sys.exit(1)
        print(f"  Loaded {len(domains)} target(s) from {target_file}\n")
    else:
        domains = [args.target.strip().lower()]

    # ── Validate at least one tool is available ───────────────────
    available = {n for n in TOOL_NAMES if check_tool(n) is not None}
    skipped = set(args.skip)
    usable = available - skipped
    if not usable:
        print(red("  ✘  No recon tools are available. Install at least one tool or adjust --skip."))
        print(yellow("     Recommended: https://github.com/projectdiscovery/subfinder"))
        sys.exit(1)

    total_start = datetime.datetime.now()
    for i, domain in enumerate(domains, 1):
        print(f"\n{'#' * 56}")
        print(f"  # Domain {i}/{len(domains)}")
        print(f"{'#' * 56}\n")
        try:
            elapsed = process_domain(domain, args, REPORTS_DIR)
            print(green(f"\n  ✔  Finished {domain} in {elapsed:.1f} s\n"))
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as e:
            print(red(f"\n  ✘  Pipeline interrupted for {domain}: {e}\n"))
        except Exception as e:
            print(red(f"\n  ✘  Unexpected error for {domain}: {e}\n"))
            import traceback
            traceback.print_exc()

    total_elapsed = (datetime.datetime.now() - total_start).total_seconds()
    print(green(f"\n{'═' * 56}"))
    print(green(f"  All done!  Total time: {total_elapsed:.1f} s"))
    print(green(f"  Reports → {REPORTS_DIR}"))
    print(green(f"{'═' * 56}\n"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(red("\n\n  ✘  Interrupted by user. Exiting."))
        sys.exit(1)
