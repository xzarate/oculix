# Oculix

Multi-source IP threat intelligence with cascade fallback.

**AbuseIPDB → VirusTotal → Shodan → AlienVault OTX**

If the primary provider hits its rate limit or fails, Oculix automatically falls to the next one. Generates CSV, TXT, HTML, and JSON reports with score, country, ISP, categories, and source for each result.

Zero external dependencies — uses only the Python 3 standard library.

---

## Requirements

- Python 3.8+
- At least one API key (recommended: AbuseIPDB + VirusTotal)

| Provider | Registration | Free tier |
|----------|-------------|-----------|
| [AbuseIPDB](https://www.abuseipdb.com) | Settings → API | 1,000 req/day |
| [VirusTotal](https://www.virustotal.com) | API key in profile | 4 req/min, 500/day |
| [Shodan](https://www.shodan.io) | Account → API | 1 req/sec (limited) |
| [AlienVault OTX](https://otx.alienvault.com) | Free account | No strict limit (works without key) |

---

## Quick start

```bash
# Clone
git clone https://github.com/xzarate/oculix.git
cd oculix

# Set API keys (optional -- can also be passed via CLI or interactive prompt)
export ABUSEIPDB_KEY="your_key"
export VIRUSTOTAL_KEY="your_key"
export SHODAN_KEY="your_key"

# Interactive mode
python3 oculix.py

# CLI mode
python3 oculix.py --file ips_ejemplo.txt
```

---

## Usage

### Interactive mode (no arguments)

```bash
python3 oculix.py
```

Guides you step by step: API keys → IP input (supports CIDR, e.g. `203.0.113.0/28`) → configuration → execution.

### CLI mode

```bash
# Single provider
python3 oculix.py --key ABUSE_KEY --file ips.txt

# Multi-source cascade
python3 oculix.py --key ABUSE_KEY --vt-key VT_KEY --shodan-key SH_KEY --file ips.txt

# IPs as arguments (supports CIDR)
python3 oculix.py --key ABUSE_KEY --ips 1.2.3.4 203.0.113.0/28

# JSON output + quiet mode (for automation)
python3 oculix.py --key ABUSE_KEY --file ips.txt --json --quiet

# Resume an interrupted run
python3 oculix.py --key ABUSE_KEY --file ips.txt --resume
```

API keys can be set via environment variables:

```bash
export ABUSEIPDB_KEY="your_key"
export VIRUSTOTAL_KEY="your_key"
export SHODAN_KEY="your_key"
export OTX_KEY="your_key"
python3 oculix.py --file ips.txt
```

---

## CLI arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--key` | env `ABUSEIPDB_KEY` | AbuseIPDB API key |
| `--vt-key` | env `VIRUSTOTAL_KEY` | VirusTotal API key |
| `--shodan-key` | env `SHODAN_KEY` | Shodan API key |
| `--otx-key` | env `OTX_KEY` | AlienVault OTX API key (optional) |
| `--file` | — | Text file with IPs (one per line, supports CIDR) |
| `--ips` | — | IPs as space-separated arguments |
| `--days` | `90` | Historical range in days |
| `--out` | `reports/ip_report` | Output file prefix |
| `--delay` | `0.6` | Seconds between requests |
| `--retries` | `3` | Retries on network/server error |
| `--resume` | `false` | Continue an interrupted run |
| `--json` | `false` | Also generate JSON report |
| `--quiet` | `false` | Suppress console output |
| `--about` | — | Show version and author info |

---

## Private / reserved IPs

Oculix automatically detects private and reserved IPs (RFC 1918, loopback, link-local, etc.) and **skips them** with a warning. Threat intelligence APIs only return meaningful data for globally routable addresses.

---

## Cascade fallback

```
AbuseIPDB --(rate limit/error)--> VirusTotal --(rate limit/error)--> Shodan --(rate limit/error)--> AlienVault OTX
```

- First provider that responds successfully wins
- Exhausted providers are skipped for the rest of the run
- If all providers are exhausted, the run stops and can be resumed with `--resume`
- The `source` field in reports indicates which provider answered each IP
- IPv6 addresses are supported across all providers (including AlienVault OTX)

---

## Output

Reports are written to the `reports/` directory by default.

| File | Content |
|------|---------|
| `reports/ip_report.csv` | Full table: source, score, country, ISP, categories, etc. |
| `reports/ip_report.txt` | Executive summary with critical IPs highlighted |
| `reports/ip_report.html` | Interactive HTML report with sortable columns |
| `reports/ip_report.json` | Machine-readable output (with `--json` flag) |

---

## Score normalization

Each provider uses its own metric, normalized to 0–100:

| Provider | Original metric | Normalization |
|----------|----------------|---------------|
| AbuseIPDB | `abuseConfidenceScore` (0–100) | Direct |
| VirusTotal | Engines malicious/suspicious vs total | `(mal + sus×0.5) / total × 100` |
| Shodan | Vulnerabilities + tags | Heuristic based on CVE count and threat tags |
| AlienVault OTX | Pulse count | 0→0, 1–2→15, 3–5→35, 6–10→55, 11–25→75, 26+→90 |

### Verdicts

| Verdict | Score |
|---------|-------|
| `MALICIOUS` | ≥ 80 |
| `SUSPICIOUS` | 25–79 |
| `LOW RISK` | 1–24 |
| `CLEAN` | 0 |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All IPs clean |
| `1` | At least one malicious IP found |
| `2` | All providers exhausted (use `--resume`) |

---

## High-volume workflow

For lists with 1,000+ IPs:

**Day 1** — run until providers are exhausted:
```bash
python3 oculix.py --key ABUSE_KEY --vt-key VT_KEY --file large_list.txt --out reports/client_x
```

**Day 2** — resume where it stopped:
```bash
python3 oculix.py --key ABUSE_KEY --vt-key VT_KEY --file large_list.txt --out reports/client_x --resume
```

---

## Repository structure

```
.
├── oculix.py          # Main tool
├── ips_ejemplo.txt    # Example IP list
├── LICENSE
└── README.md
```

---

## Author

**Alexis Zarate**
- GitHub: [github.com/xzarate](https://github.com/xzarate)
- LinkedIn: [linkedin.com/in/alexiszarate](https://www.linkedin.com/in/alexiszarate/)

---

## License

[MIT](LICENSE)
