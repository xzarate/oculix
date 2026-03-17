#!/usr/bin/env python3
"""
Oculix -- Multi-Source IP Threat Intelligence

Providers (cascade fallback): AbuseIPDB -> VirusTotal -> Shodan -> AlienVault OTX
Reports are saved to the reports/ directory by default.

Usage:
  Interactive:        python3 oculix.py
  From file:          python3 oculix.py --key YOUR_API_KEY --file ips.txt
  By argument:        python3 oculix.py --key YOUR_API_KEY --ips 1.2.3.4 5.6.7.8
  CIDR support:       python3 oculix.py --key YOUR_API_KEY --ips 203.0.113.0/24
  Multi-source:       python3 oculix.py --key ABUSE_KEY --vt-key VT_KEY --file ips.txt
  Named report:       python3 oculix.py --key YOUR_API_KEY --file ips.txt --report-name incident_01
  JSON output:        python3 oculix.py --key YOUR_API_KEY --file ips.txt --json
  Quiet mode:         python3 oculix.py --key YOUR_API_KEY --file ips.txt --quiet
  Resume:             python3 oculix.py --key YOUR_API_KEY --file ips.txt --resume

https://github.com/xzarate/oculix
"""

import argparse, csv, ipaddress, json, os, sys, time
from datetime import datetime, timezone
from html import escape as html_escape
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Enable ANSI escape sequences on Windows
if sys.platform == "win32":
    os.system("")

VERSION = "2.0.0"
QUIET = False
MAX_CIDR_HOSTS = 4096

# ── ANSI color constants ──
G   = "\033[32m"
BG  = "\033[92m"
C   = "\033[36m"
BC  = "\033[96m"
W   = "\033[97m"
Y   = "\033[33m"
RED = "\033[91m"
DM  = "\033[2m"
B   = "\033[1m"
R   = "\033[0m"

VERDICT_COLOR = {
    "MALICIOUS":  RED,
    "SUSPICIOUS": Y,
    "LOW RISK":   BC,
    "CLEAN":      BG,
    "ERROR":      DM,
}

# ── Exit codes ──
EXIT_CLEAN     = 0
EXIT_MALICIOUS = 1
EXIT_EXHAUSTED = 2

# ── Banner ──
BANNER = """\
     ██████╗  ██████╗██╗   ██╗██╗     ██╗██╗  ██╗
    ██╔═══██╗██╔════╝██║   ██║██║     ██║╚██╗██╔╝
    ██║   ██║██║     ██║   ██║██║     ██║ ╚███╔╝
    ██║   ██║██║     ██║   ██║██║     ██║ ██╔██╗
    ╚██████╔╝╚██████╗╚██████╔╝███████╗██║██╔╝ ██╗
     ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝"""

# Demo IPs (RFC 5737 doc ranges + public DNS) -- safe for public repos
DEFAULT_IPS = [
    "192.0.2.1", "192.0.2.10", "192.0.2.50",       # RFC 5737 TEST-NET-1
    "198.51.100.1", "198.51.100.25",                 # RFC 5737 TEST-NET-2
    "203.0.113.1", "203.0.113.100",                  # RFC 5737 TEST-NET-3
    "8.8.8.8", "1.1.1.1", "9.9.9.9",                # Public DNS (clean)
]

CATEGORIES = {
    1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",
    5:"FTP Brute-Force",6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",
    9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",13:"VPN IP",
    14:"Port Scan",15:"Hacking",16:"SQL Injection",17:"Spoofing",18:"Brute-Force",
    19:"Bad Web Bot",20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted",
}

FIELDNAMES = ["ip","source","verdict","abuse_score","total_reports","distinct_users",
              "country","isp","domain","usage_type","is_tor","last_reported","categories"]

# Providers marked as exhausted (rate limited) during execution
_exhausted = set()


# ── Logging ──

def log(*args, **kwargs):
    """Print only when not in quiet mode."""
    if not QUIET:
        print(*args, **kwargs)


# ── Banner / About ──

def print_banner():
    if QUIET:
        return
    for line in BANNER.splitlines():
        print(f"{B}{G}{line}{R}")
    print(f"{C}    Multi-Source IP Threat Intelligence{R}")
    print(f"{DM}    {'─' * 48}{R}")
    print(f"{DM}    v{VERSION}  ·  github.com/xzarate{R}")
    print(f"{DM}    linkedin.com/in/alexiszarate{R}")
    print()


def print_about():
    print_banner()


# ── Utilities ──

def is_valid_ip(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_private_ip(addr):
    """Return True if the IP is private, reserved, loopback, or otherwise not globally routable."""
    try:
        ip = ipaddress.ip_address(addr)
        return not ip.is_global
    except ValueError:
        return False


def expand_cidr(token):
    """Expand CIDR notation to list of host IPs. Returns None if not CIDR."""
    if "/" not in token:
        return None
    try:
        network = ipaddress.ip_network(token.strip(), strict=False)
        num = network.num_addresses
        if num <= 1:
            return None
        if num > MAX_CIDR_HOSTS:
            log(f"  [WARN] CIDR {token} contains {num} hosts (max {MAX_CIDR_HOSTS}). Truncating.")
        hosts = []
        for i, ip in enumerate(network.hosts()):
            if i >= MAX_CIDR_HOSTS:
                break
            hosts.append(str(ip))
        return hosts if hosts else None
    except ValueError:
        return None


def load_ips_from_file(path):
    ips = []
    private_count = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cidr_result = expand_cidr(line)
            if cidr_result is not None:
                ips.extend(cidr_result)
                continue
            ip = line.split()[0]
            if is_valid_ip(ip):
                if is_private_ip(ip):
                    private_count += 1
                ips.append(ip)
            else:
                log(f"  [WARN] Ignored: {line}")
    if private_count:
        log(f"  [WARN] {private_count} private/reserved IP(s) detected -- they will be skipped during execution.")
    return ips


def load_already_done(csv_path):
    done = set()
    if not os.path.exists(csv_path):
        return done
    with open(csv_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("ip"):
                done.add(row["ip"])
    return done


def deduplicate(ips):
    seen = set()
    result = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def verdict(score):
    if score >= 80: return "MALICIOUS"
    if score >= 25: return "SUSPICIOUS"
    if score >  0:  return "LOW RISK"
    return "CLEAN"


def fmt_cats(cat_ids):
    return "; ".join(CATEGORIES.get(c, str(c)) for c in sorted(cat_ids))


def parse_raw_ips(text):
    tokens = text.replace(",", " ").replace(";", " ").split()
    valid, invalid = [], []
    for t in tokens:
        cidr_result = expand_cidr(t)
        if cidr_result is not None:
            valid.extend(cidr_result)
        elif is_valid_ip(t):
            valid.append(t)
        else:
            invalid.append(t)
    return valid, invalid


def ask_option(prompt, valid_options, default=None):
    while True:
        choice = input(prompt).strip()
        if not choice and default is not None:
            return default
        if choice in valid_options:
            return choice
        print(f"  Invalid option. Options: {', '.join(valid_options)}")


def migrate_csv_if_needed(csv_path):
    """Add 'source' column to CSVs from the old format (backward compat)."""
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        return
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if "source" in (reader.fieldnames or []):
            return
        rows = list(reader)
    tmp = csv_path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            row["source"] = "AbuseIPDB"
            writer.writerow(row)
    os.replace(tmp, csv_path)
    log(f"[MIGRATE] CSV updated with 'source' column ({len(rows)} rows).")


# ── Provider: AbuseIPDB ──

def query_abuseipdb(ip, api_key, max_age_days, retries=3, backoff=5.0):
    if not api_key or "abuseipdb" in _exhausted:
        return None
    url = (f"https://api.abuseipdb.com/api/v2/check"
           f"?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose=true")
    req = Request(url, headers={"Key": api_key, "Accept": "application/json"})

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode()).get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            cat_ids = set()
            for rep in data.get("reports", []):
                cat_ids.update(rep.get("categories", []))
            last_r = data.get("lastReportedAt") or "-"
            return {
                "source": "AbuseIPDB",
                "score": score,
                "total_reports": data.get("totalReports", 0),
                "distinct_users": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode", "-"),
                "isp": data.get("isp", "-"),
                "domain": data.get("domain", "-"),
                "usage_type": data.get("usageType", "-"),
                "is_tor": bool(data.get("isTor")),
                "last_reported": last_r[:10] if last_r != "-" else "-",
                "categories": fmt_cats(cat_ids),
            }
        except HTTPError as e:
            e.read()
            if e.code == 429:
                _exhausted.add("abuseipdb")
                log("[AbuseIPDB rate limit]", end=" ", flush=True)
                return None
            if e.code in (401, 403):
                _exhausted.add("abuseipdb")
                log(f"[AbuseIPDB auth error {e.code}]", end=" ", flush=True)
                return None
            if e.code >= 500:
                time.sleep(backoff * attempt)
            else:
                return None
        except URLError:
            time.sleep(backoff * attempt)

    return None


# ── Provider: VirusTotal ──

def query_virustotal(ip, api_key, retries=3, backoff=5.0):
    if not api_key or "virustotal" in _exhausted:
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = Request(url, headers={"x-apikey": api_key, "Accept": "application/json"})

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode()).get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = min(100, int((mal + sus * 0.5) / total * 100))
            ts = attrs.get("last_analysis_date")
            if ts and isinstance(ts, (int, float)):
                last_r = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
            else:
                last_r = "-"
            tags = attrs.get("tags", [])
            return {
                "source": "VirusTotal",
                "score": score,
                "total_reports": mal + sus,
                "distinct_users": mal,
                "country": attrs.get("country", "-") or "-",
                "isp": attrs.get("as_owner", "-") or "-",
                "domain": "-",
                "usage_type": "-",
                "is_tor": any("tor" in t.lower() for t in tags),
                "last_reported": last_r,
                "categories": "-",
            }
        except HTTPError as e:
            e.read()
            if e.code == 429:
                _exhausted.add("virustotal")
                log("[VT rate limit]", end=" ", flush=True)
                return None
            if e.code in (401, 403):
                _exhausted.add("virustotal")
                log(f"[VT auth error {e.code}]", end=" ", flush=True)
                return None
            if e.code >= 500:
                time.sleep(backoff * attempt)
            else:
                return None
        except URLError:
            time.sleep(backoff * attempt)

    return None


# ── Provider: Shodan ──

def query_shodan(ip, api_key, retries=3, backoff=5.0):
    if not api_key or "shodan" in _exhausted:
        return None
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    req = Request(url, headers={"Accept": "application/json"})

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            vulns = data.get("vulns", [])
            tags = data.get("tags", [])
            ports = data.get("ports", [])

            # Score heuristic based on vulnerabilities and tags
            score = 0
            if any(t in tags for t in ("malware", "compromised", "c2", "botnet", "phishing")):
                score = 85
            elif len(vulns) > 25:
                score = 90
            elif len(vulns) > 10:
                score = 55
            elif len(vulns) > 5:
                score = 35
            elif len(vulns) > 0:
                score = 20
            elif len(ports) > 30:
                score = 10

            # Boost if known Tor exit
            if any("tor" in t.lower() for t in tags):
                score = max(score, 25)

            last_update = data.get("last_update", "") or ""
            return {
                "source": "Shodan",
                "score": score,
                "total_reports": len(vulns),
                "distinct_users": len(ports),
                "country": data.get("country_code", "-") or "-",
                "isp": data.get("org", "-") or "-",
                "domain": ", ".join(data.get("domains", [])[:3]) or "-",
                "usage_type": "-",
                "is_tor": any("tor" in t.lower() for t in tags),
                "last_reported": last_update[:10] if last_update else "-",
                "categories": "; ".join(vulns[:5]) if vulns else ("-" if not tags else "; ".join(tags[:5])),
            }
        except HTTPError as e:
            e.read()
            if e.code == 404:
                # IP not found in Shodan database -- let next provider try
                return None
            if e.code == 429:
                _exhausted.add("shodan")
                log("[Shodan rate limit]", end=" ", flush=True)
                return None
            if e.code in (401, 403):
                _exhausted.add("shodan")
                log(f"[Shodan auth error {e.code}]", end=" ", flush=True)
                return None
            if e.code >= 500:
                time.sleep(backoff * attempt)
            else:
                return None
        except URLError:
            time.sleep(backoff * attempt)

    return None


# ── Provider: AlienVault OTX ──

def query_otx(ip, api_key=None, retries=3, backoff=5.0):
    if "otx" in _exhausted:
        return None
    try:
        version = "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"
    except ValueError:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/{version}/{ip}/general"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    req = Request(url, headers=headers)

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            pulses = data.get("pulse_info", {}).get("count", 0)
            if pulses == 0:     score = 0
            elif pulses <= 2:   score = 15
            elif pulses <= 5:   score = 35
            elif pulses <= 10:  score = 55
            elif pulses <= 25:  score = 75
            else:               score = 90
            return {
                "source": "AlienVault OTX",
                "score": score,
                "total_reports": pulses,
                "distinct_users": 0,
                "country": data.get("country_code", "-") or "-",
                "isp": data.get("asn", "-") or "-",
                "domain": "-",
                "usage_type": "-",
                "is_tor": False,
                "last_reported": "-",
                "categories": "-",
            }
        except HTTPError as e:
            e.read()
            if e.code in (429, 403):
                _exhausted.add("otx")
                log("[OTX limit]", end=" ", flush=True)
                return None
            if e.code >= 500:
                time.sleep(backoff * attempt)
            else:
                return None
        except URLError:
            time.sleep(backoff * attempt)

    return None


# ── Cascade ──

def query_ip(ip, keys, max_age_days, retries=3):
    """Cascade: AbuseIPDB -> VirusTotal -> Shodan -> AlienVault OTX."""
    result = query_abuseipdb(ip, keys.get("abuseipdb"), max_age_days, retries)
    if result:
        return result

    result = query_virustotal(ip, keys.get("virustotal"), retries)
    if result:
        return result

    result = query_shodan(ip, keys.get("shodan"), retries)
    if result:
        return result

    result = query_otx(ip, keys.get("otx"), retries)
    if result:
        return result

    return None


# ── Output: CSV ──

def append_csv(csv_path, row, write_header):
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if write_header:
            w.writeheader()
        w.writerow(row)


# ── Output: TXT ──

def write_txt(txt_path, results, days, csv_path):
    counts = {}
    sources = set()
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        src = r.get("source", "-")
        if src and src != "-":
            sources.add(src)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("OCULIX - IP THREAT INTELLIGENCE REPORT\n")
        f.write(f"Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Sources     : {', '.join(sorted(sources)) or '-'}\n")
        f.write(f"Range       : last {days} days\n")
        f.write(f"Total IPs   : {len(results)}\n")
        f.write("=" * 60 + "\n\n")
        f.write("SUMMARY\n" + "-" * 40 + "\n")
        for k in ("MALICIOUS","SUSPICIOUS","LOW RISK","CLEAN","ERROR"):
            v = counts.get(k, 0)
            if v:
                f.write(f"  {k:<12}: {v}\n")
        f.write("\n")
        for label, filt in [("MALICIOUS IPs","MALICIOUS"),("SUSPICIOUS IPs","SUSPICIOUS")]:
            group = [r for r in results if r["verdict"] == filt]
            if not group:
                continue
            f.write(f"{label}\n" + "-" * 40 + "\n")
            for r in group:
                src = r.get("source", "-")
                f.write(f"  {r['ip']:<20} score={r['abuse_score']:>3} | {r['country']} | {r['isp']} [{src}]\n")
                if r["categories"] and r["categories"] != "-":
                    f.write(f"    Categories     : {r['categories']}\n")
                f.write(f"    Last reported  : {r['last_reported']}\n\n")
        f.write("=" * 60 + "\n")
        f.write(f"Full CSV: {csv_path}\n")
        f.write(f"Generated by Oculix v{VERSION}\n")


# ── Output: JSON ──

def write_json(json_path, results, days, sources_used, counts):
    data = {
        "tool": "Oculix",
        "version": VERSION,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sources": sorted(sources_used),
        "range_days": days,
        "total_ips": len(results),
        "summary": {k: counts.get(k, 0) for k in ("MALICIOUS", "SUSPICIOUS", "LOW RISK", "CLEAN", "ERROR")},
        "results": results,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ── Output: HTML ──

def write_html(html_path, results, days, csv_path):
    counts = {}
    sources = set()
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        src = r.get("source", "-")
        if src and src != "-":
            sources.add(src)

    verdict_colors = {
        "MALICIOUS": "#ff4444", "SUSPICIOUS": "#ffaa00",
        "LOW RISK": "#4488ff", "CLEAN": "#44ff88", "ERROR": "#888888",
    }

    rows_html = ""
    for r in results:
        color = verdict_colors.get(r.get("verdict", ""), "#ffffff")
        rows_html += "<tr>"
        rows_html += f"<td><code>{html_escape(r.get('ip', '-'))}</code></td>"
        rows_html += f"<td>{html_escape(r.get('source', '-'))}</td>"
        rows_html += f"<td style=\"color:{color};font-weight:bold\">{html_escape(r.get('verdict', '-'))}</td>"
        rows_html += f"<td>{html_escape(str(r.get('abuse_score', '-')))}</td>"
        rows_html += f"<td>{html_escape(str(r.get('total_reports', '-')))}</td>"
        rows_html += f"<td>{html_escape(r.get('country', '-'))}</td>"
        rows_html += f"<td>{html_escape(r.get('isp', '-'))}</td>"
        rows_html += f"<td>{html_escape(r.get('domain', '-'))}</td>"
        rows_html += f"<td>{html_escape(r.get('is_tor', '-'))}</td>"
        rows_html += f"<td>{html_escape(r.get('last_reported', '-'))}</td>"
        rows_html += f"<td>{html_escape(r.get('categories', '-'))}</td>"
        rows_html += "</tr>\n"

    cards_html = ""
    for label in ("MALICIOUS", "SUSPICIOUS", "LOW RISK", "CLEAN", "ERROR"):
        count = counts.get(label, 0)
        if count:
            color = verdict_colors[label]
            cards_html += (
                f'<div class="card">'
                f'<div class="number" style="color:{color}">{count}</div>'
                f'<div class="label">{label}</div>'
                f'</div>\n'
            )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Oculix - IP Threat Intelligence Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0a1a;color:#e0e0e0;padding:30px}}
.container{{max-width:1500px;margin:0 auto}}
h1{{color:#44ff88;text-align:center;font-size:2.4em;letter-spacing:4px;margin-bottom:5px}}
.subtitle{{text-align:center;color:#666;margin-bottom:30px;font-size:0.9em}}
.summary{{display:flex;gap:15px;justify-content:center;margin-bottom:30px;flex-wrap:wrap}}
.card{{background:#12122a;border:1px solid #222;border-radius:10px;padding:18px 30px;text-align:center;min-width:130px}}
.card .number{{font-size:2.2em;font-weight:bold}}
.card .label{{font-size:0.8em;color:#888;text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:#12122a;border-radius:10px;overflow:hidden}}
th{{background:#1a1a3a;padding:12px 10px;text-align:left;font-size:0.78em;text-transform:uppercase;letter-spacing:1px;color:#888;cursor:pointer;user-select:none}}
th:hover{{color:#44ff88}}
td{{padding:10px;border-bottom:1px solid #1a1a2a;font-size:0.85em}}
tr:hover{{background:#1a1a30}}
code{{background:#1a1a3a;padding:2px 6px;border-radius:3px;font-size:0.9em}}
.footer{{text-align:center;margin-top:30px;color:#444;font-size:0.8em}}
a{{color:#44ff88;text-decoration:none}}
a:hover{{text-decoration:underline}}
</style>
</head>
<body>
<div class="container">
<h1>OCULIX</h1>
<p class="subtitle">
IP Threat Intelligence Report &middot;
{html_escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} &middot;
Sources: {html_escape(', '.join(sorted(sources)) or '-')} &middot;
Range: {days} days &middot;
Total: {len(results)} IPs
</p>
<div class="summary">
{cards_html}
</div>
<div class="table-wrap">
<table id="results">
<thead><tr>
<th>IP</th><th>Source</th><th>Verdict</th><th>Score</th><th>Reports</th>
<th>Country</th><th>ISP</th><th>Domain</th><th>Tor</th><th>Last Reported</th><th>Categories</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>
<div class="footer">
Generated by <strong>Oculix v{VERSION}</strong> &middot;
<a href="https://github.com/xzarate">GitHub</a> &middot;
<a href="https://www.linkedin.com/in/alexiszarate/">Alexis Zarate</a>
</div>
</div>
<script>
document.querySelectorAll('#results th').forEach((th,i)=>{{
  th.addEventListener('click',()=>{{
    const tb=th.closest('table').querySelector('tbody');
    const rows=[...tb.rows];
    const asc=th.dataset.asc!=='1';
    rows.sort((a,b)=>{{
      let x=a.cells[i].textContent,y=b.cells[i].textContent;
      let nx=parseFloat(x),ny=parseFloat(y);
      if(!isNaN(nx)&&!isNaN(ny)) return asc?nx-ny:ny-nx;
      return asc?x.localeCompare(y):y.localeCompare(x);
    }});
    rows.forEach(r=>tb.appendChild(r));
    th.dataset.asc=asc?'1':'0';
  }});
}});
</script>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(page)


# ── Interactive mode ──

def interactive_mode():
    # -- API Keys --
    print("-- API Keys --")
    print(f"  {C}Cascade: AbuseIPDB > VirusTotal > Shodan > AlienVault OTX{R}\n")

    key_defs = [
        ("AbuseIPDB",      "ABUSEIPDB_KEY",   "abuseipdb",  None),
        ("VirusTotal",     "VIRUSTOTAL_KEY",   "virustotal", None),
        ("Shodan",         "SHODAN_KEY",       "shodan",     None),
        ("AlienVault OTX", "OTX_KEY",          "otx",        "works without key, with limits"),
    ]

    keys = {}
    missing = []

    for name, env_var, key_id, note in key_defs:
        val = os.environ.get(env_var, "")
        if val:
            masked = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
            print(f"  {name:<16}: {BG}env var{R} ({masked})")
            keys[key_id] = val
        else:
            extra = f" ({note})" if note else ""
            print(f"  {name:<16}: {Y}not set{R}{extra}")
            missing.append((name, env_var, key_id, note))
            keys[key_id] = None

    # Only prompt for missing keys
    if missing:
        print(f"\n  {C}Configure missing keys:{R}")
        for name, env_var, key_id, note in missing:
            print(f"\n  {name}:")
            if note:
                print(f"    {DM}{note}{R}")
            opt = ask_option(
                "    1) Enter key\n"
                "    2) Skip (source will be bypassed)\n\n"
                f"    {Y}Option: {R}", ["1", "2"])
            if opt == "1":
                key = input(f"    {Y}API key: {R}").strip()
                keys[key_id] = key or None
    else:
        print(f"\n  {BG}All keys configured.{R}")

    providers = []
    if keys["abuseipdb"]:  providers.append("AbuseIPDB")
    if keys["virustotal"]: providers.append("VirusTotal")
    if keys["shodan"]:     providers.append("Shodan")
    providers.append("AlienVault OTX")

    if not keys["abuseipdb"] and not keys["virustotal"] and not keys["shodan"]:
        print(f"\n  [WARN] No AbuseIPDB, VirusTotal, or Shodan key.")
        print(f"         Only AlienVault OTX will be available.")

    print(f"\n  [OK] Cascade: {' > '.join(providers)}")

    # -- IP input (supports CIDR) --
    print("\n-- IPs to query (supports CIDR, e.g. 203.0.113.0/24) --")
    print("  Enter IPs separated by comma, space, or one per line.")
    print("  Empty line to finish:\n")
    lines = []
    while True:
        line = input("  > ").strip()
        if not line:
            break
        lines.append(line)
    if not lines:
        print("\n[ERROR] No IPs entered."); sys.exit(1)
    valid, invalid = parse_raw_ips(" ".join(lines))
    if invalid:
        print(f"\n  [WARN] Ignored ({len(invalid)}): {', '.join(invalid)}")
    ips = valid
    if not ips:
        print("\n[ERROR] No valid IPs entered."); sys.exit(1)

    ips = deduplicate(ips)

    # -- Show IPs --
    print(f"\n-- IPs to query ({len(ips)}) --")
    show_limit = min(len(ips), 50)
    for i, ip in enumerate(ips[:show_limit], 1):
        print(f"  {i:>3}. {ip}")
    if len(ips) > show_limit:
        print(f"  ... and {len(ips) - show_limit} more")

    # -- Confirm --
    opt = ask_option(
        f"\n  Proceed with these {len(ips)} IPs?\n"
        f"  1) Yes, continue\n"
        f"  2) No, cancel\n\n"
        f"  {Y}Option [1]: {R}", ["1", "2"], "1")
    if opt == "2":
        print("\n  Cancelled."); sys.exit(0)

    # -- Report folder name --
    print(f"\n-- Report folder --")
    default_name = f"oculix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"  Reports will be saved under {C}reports/<name>/{R}")
    report_name = input(f"  Folder name [{default_name}]: ").strip()
    if not report_name:
        report_name = default_name
    # Sanitize: remove path separators and dangerous chars
    report_name = report_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    out = f"reports/{report_name}/ip_report"
    print(f"  {BG}Output folder:{R} reports/{report_name}/")

    # -- Configuration --
    days = 90
    delay = 0.6
    retries_n = 3
    resume = False
    use_json = False

    print("\n-- Configuration --")
    while True:
        print(f"  1) Day range        : {days}")
        print(f"  2) Request delay    : {delay}s")
        print(f"  3) Retries          : {retries_n}")
        print(f"  4) Output prefix    : {out}")
        print(f"  5) Resume           : {'Yes' if resume else 'No'}")
        print(f"  6) JSON output      : {'Yes' if use_json else 'No'}")
        print(f"  0) Continue >>")
        opt = ask_option(f"\n  {Y}Modify [0-6] [0]: {R}", ["0","1","2","3","4","5","6"], "0")
        if opt == "0":
            break
        elif opt == "1":
            v = input(f"    New day range [{days}]: ").strip()
            if v:
                try: days = int(v)
                except ValueError: print("    Invalid value, keeping previous.")
        elif opt == "2":
            v = input(f"    New delay in seconds [{delay}]: ").strip()
            if v:
                try: delay = float(v)
                except ValueError: print("    Invalid value, keeping previous.")
        elif opt == "3":
            v = input(f"    New retries [{retries_n}]: ").strip()
            if v:
                try: retries_n = int(v)
                except ValueError: print("    Invalid value, keeping previous.")
        elif opt == "4":
            v = input(f"    New prefix [{out}]: ").strip()
            if v: out = v
        elif opt == "5":
            resume = not resume
            print(f"    Resume: {'Yes' if resume else 'No'}")
        elif opt == "6":
            use_json = not use_json
            print(f"    JSON output: {'Yes' if use_json else 'No'}")
        print()

    # -- Final summary --
    print(f"\n{'='*60}")
    print(f"  IPs        : {len(ips)}")
    print(f"  Cascade    : {' > '.join(providers)}")
    print(f"  Range      : {days} days")
    print(f"  Delay      : {delay}s")
    print(f"  Retries    : {retries_n}")
    print(f"  Output     : {out}.csv / {out}.txt / {out}.html")
    if use_json:
        print(f"               {out}.json")
    print(f"  Resume     : {'Yes' if resume else 'No'}")
    print(f"{'='*60}")

    opt = ask_option(
        f"\n  Execute?\n"
        f"  1) Yes, run\n"
        f"  2) No, cancel\n\n"
        f"  {Y}Option [1]: {R}", ["1", "2"], "1")
    if opt == "2":
        print("\n  Cancelled."); sys.exit(0)

    return keys, ips, days, delay, retries_n, out, resume, use_json


# ── Main ──

def main():
    global QUIET

    # Handle --about early (before argparse)
    if "--about" in sys.argv:
        print_about()
        sys.exit(0)

    # No CLI arguments -> interactive mode
    if len(sys.argv) == 1:
        print_banner()
        keys, ips, days, delay, retries_n, out, resume, use_json = interactive_mode()
    else:
        # Direct CLI mode
        parser = argparse.ArgumentParser(
            description="Oculix -- Multi-Source IP Threat Intelligence",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog="""Providers (cascade): AbuseIPDB -> VirusTotal -> Shodan -> AlienVault OTX

Examples:
  python3 oculix.py --key MY_KEY
  python3 oculix.py --key MY_KEY --file ips.txt
  python3 oculix.py --key MY_KEY --vt-key VT_KEY --shodan-key SH_KEY --file ips.txt
  python3 oculix.py --key MY_KEY --ips 1.2.3.4 5.6.7.8
  python3 oculix.py --key MY_KEY --ips 203.0.113.0/28
  python3 oculix.py --key MY_KEY --file ips.txt --report-name incident_01
  python3 oculix.py --key MY_KEY --file ips.txt --json --quiet
  python3 oculix.py --key MY_KEY --file ips.txt --resume"""
        )
        parser.add_argument("--key",        default=os.environ.get("ABUSEIPDB_KEY"),
                            help="AbuseIPDB API key (or env ABUSEIPDB_KEY)")
        parser.add_argument("--vt-key",     default=os.environ.get("VIRUSTOTAL_KEY"),
                            help="VirusTotal API key (or env VIRUSTOTAL_KEY)")
        parser.add_argument("--shodan-key", default=os.environ.get("SHODAN_KEY"),
                            help="Shodan API key (or env SHODAN_KEY)")
        parser.add_argument("--otx-key",    default=os.environ.get("OTX_KEY"),
                            help="AlienVault OTX API key (or env OTX_KEY, optional)")
        parser.add_argument("--days",       type=int,   default=90,  help="Day range (default: 90)")
        parser.add_argument("--out",        default="reports/ip_report", help="Output prefix (default: reports/ip_report)")
        parser.add_argument("--file",                                help="Text file with IPs (supports CIDR)")
        parser.add_argument("--ips",        nargs="+",               help="IPs as arguments (supports CIDR)")
        parser.add_argument("--resume",     action="store_true",     help="Resume interrupted run")
        parser.add_argument("--delay",      type=float, default=0.6, help="Delay between requests (default: 0.6s)")
        parser.add_argument("--retries",    type=int,   default=3,   help="Retries on error (default: 3)")
        parser.add_argument("--json",       action="store_true",     help="Write JSON report ({out}.json)")
        parser.add_argument("--quiet", "-q",action="store_true",     help="Suppress console output")
        parser.add_argument("--report-name",default=None,            help="Report folder name (created under reports/)")
        parser.add_argument("--about",      action="store_true",     help="Show author and project info")
        args = parser.parse_args()

        if args.quiet:
            QUIET = True

        print_banner()

        keys = {
            "abuseipdb":  args.key,
            "virustotal": args.vt_key,
            "shodan":     args.shodan_key,
            "otx":        args.otx_key,
        }

        if not keys["abuseipdb"] and not keys["virustotal"] and not keys["shodan"]:
            log("[WARN] No AbuseIPDB, VirusTotal, or Shodan key. Only AlienVault OTX available.")

        if args.file:
            try:
                ips = load_ips_from_file(args.file)
            except FileNotFoundError:
                print(f"[ERROR] File not found: {args.file}"); sys.exit(1)
            if not ips:
                print(f"[ERROR] No valid IPs in '{args.file}'."); sys.exit(1)
            log(f"[INFO] {len(ips)} IPs from '{args.file}'")
        elif args.ips:
            raw_valid, raw_invalid = [], []
            for token in args.ips:
                cidr_result = expand_cidr(token)
                if cidr_result is not None:
                    raw_valid.extend(cidr_result)
                elif is_valid_ip(token):
                    raw_valid.append(token)
                else:
                    raw_invalid.append(token)
            if raw_invalid:
                log(f"[WARN] Ignored: {', '.join(raw_invalid)}")
            ips = raw_valid
            if not ips:
                print("[ERROR] No valid IPs."); sys.exit(1)
            log(f"[INFO] {len(ips)} IPs from --ips")
        else:
            ips = DEFAULT_IPS
            log(f"[INFO] Using {len(ips)} default IPs")

        days = args.days
        delay = args.delay
        retries_n = args.retries
        if args.report_name:
            name = args.report_name.replace("/", "_").replace("\\", "_").replace("..", "_")
            out = f"reports/{name}/ip_report"
        else:
            out = args.out
        resume = args.resume
        use_json = args.json

    # ── Common execution ──
    ips = deduplicate(ips)

    csv_path  = f"{out}.csv"
    txt_path  = f"{out}.txt"
    html_path = f"{out}.html"
    json_path = f"{out}.json"

    out_dir = os.path.dirname(csv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Resume: migrate old CSV if needed and load already-processed IPs
    already_done = set()
    if resume:
        migrate_csv_if_needed(csv_path)
        already_done = load_already_done(csv_path)
        if already_done:
            log(f"[RESUME] {len(already_done)} IPs already processed -- skipped.")

    pending = [ip for ip in ips if ip not in already_done]
    total   = len(ips)
    done_n  = len(already_done)

    if not pending:
        log("[INFO] All IPs already processed."); sys.exit(EXIT_CLEAN)

    # Show available providers
    providers = []
    if keys.get("abuseipdb"):  providers.append("AbuseIPDB")
    if keys.get("virustotal"): providers.append("VirusTotal")
    if keys.get("shodan"):     providers.append("Shodan")
    providers.append("AlienVault OTX")

    log(f"\n{'='*60}")
    log(f"  Total: {total}  |  Pending: {len(pending)}  |  Done: {done_n}")
    log(f"  Cascade: {' > '.join(providers)}")
    log(f"  Range: {days} days  |  Delay: {delay}s  |  Retries: {retries_n}")
    log(f"  Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"{'='*60}\n")

    write_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
    all_exhausted_final = False

    for i, ip in enumerate(pending, 1):
        idx = done_n + i
        log(f"[{idx:>4}/{total}] {ip:<20}", end=" ", flush=True)

        if is_private_ip(ip):
            row = {k: "-" for k in FIELDNAMES}
            row["ip"] = ip
            row["source"] = "-"
            row["verdict"] = "ERROR"
            row["categories"] = "Private/reserved IP"
            log(f"{Y}SKIPPED{R} -- private or reserved IP (not globally routable)")
            append_csv(csv_path, row, write_header=(write_header and i == 1))
            continue

        result = query_ip(ip, keys, days, retries_n)

        if result is None:
            row = {k: "-" for k in FIELDNAMES}
            row["ip"] = ip
            row["source"] = "-"
            row["verdict"] = "ERROR"
            log("ERROR (no providers available)")
        else:
            v = verdict(result["score"])
            row = {
                "ip": ip,
                "source": result["source"],
                "verdict": v,
                "abuse_score": result["score"],
                "total_reports": result["total_reports"],
                "distinct_users": result["distinct_users"],
                "country": result["country"],
                "isp": result["isp"],
                "domain": result["domain"],
                "usage_type": result["usage_type"],
                "is_tor": "Yes" if result["is_tor"] else "No",
                "last_reported": result["last_reported"],
                "categories": result["categories"],
            }
            color = VERDICT_COLOR.get(v, W)
            tag = {"MALICIOUS":"!! MALICIOUS","SUSPICIOUS":"?? SUSPICIOUS",
                   "LOW RISK":"~~ LOW RISK","CLEAN":"OK CLEAN"}.get(v, v)
            isp = row["isp"][:28]
            log(f"{color}{tag:16}{R} score={result['score']:3d} | rep={result['total_reports']:3d} | {row['country']} | {isp} [{result['source']}]")

        append_csv(csv_path, row, write_header=(write_header and i == 1))

        # If all providers are exhausted, stop
        all_exhausted = (
            ("abuseipdb" in _exhausted or not keys.get("abuseipdb"))
            and ("virustotal" in _exhausted or not keys.get("virustotal"))
            and ("shodan" in _exhausted or not keys.get("shodan"))
            and "otx" in _exhausted
        )
        if all_exhausted:
            log(f"\n[FATAL] All providers exhausted. Resume with --resume.\n")
            all_exhausted_final = True
            break

        time.sleep(delay)

    # Read full CSV for final report (including previous runs)
    all_results = []
    with open(csv_path, "r", encoding="utf-8") as f:
        all_results = list(csv.DictReader(f))

    # Collect stats
    sources_used = set()
    counts = {}
    for r in all_results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        src = r.get("source", "-")
        if src and src != "-":
            sources_used.add(src)

    # Write reports
    write_txt(txt_path, all_results, days, csv_path)
    write_html(html_path, all_results, days, csv_path)

    if use_json:
        write_json(json_path, all_results, days, sources_used, counts)

    # Final summary
    log(f"\n{'='*60}")
    log(f"  FINAL SUMMARY ({len(all_results)} IPs)")
    log(f"  Sources: {', '.join(sorted(sources_used)) or '-'}")
    log(f"{'='*60}")
    for k in ("MALICIOUS","SUSPICIOUS","LOW RISK","CLEAN","ERROR"):
        v = counts.get(k, 0)
        if v:
            color = VERDICT_COLOR.get(k, W)
            log(f"  {color}{k:<12}{R}: {v}")
    log(f"\n  {csv_path}")
    log(f"  {txt_path}")
    log(f"  {html_path}")
    if use_json:
        log(f"  {json_path}")
    log(f"{'='*60}\n")

    # Exit code
    if all_exhausted_final:
        sys.exit(EXIT_EXHAUSTED)
    elif counts.get("MALICIOUS", 0) > 0:
        sys.exit(EXIT_MALICIOUS)
    else:
        sys.exit(EXIT_CLEAN)


if __name__ == "__main__":
    main()
