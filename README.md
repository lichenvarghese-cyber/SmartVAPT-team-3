# 🛡️ SmartVAPT — Tri-Vector Attack Surface Analyzer & AI Reporting Engine

SmartVAPT is an automated Vulnerability Assessment & Penetration Testing (VAPT) tool with a Streamlit dashboard. It combines **three core scan vectors** — network, web application, and DNS/email security — into one workflow and adds provider-aware scan guardrails, deterministic compliance mapping, per-finding fix verification, and a professional evidence-backed **PDF report**. Reports can be enriched with narratives from a **local small language model (Ollama)** — no cloud API keys and no scan data leaving the machine.

Built as part of the **ICT Academy of Kerala – Cyber Security Analyst (VAPT)** program.

---

## ⚠️ Legal Disclaimer / Authorized Use Only

Scanning networks and applications you do not own or have **written permission** to test is illegal in most jurisdictions. Use SmartVAPT only against:

- Systems you own
- Targets with explicit written authorization (e.g., a signed scope document)
- Public test targets such as `scanme.nmap.org` or DVWA-style labs

Provider guardrails reduce load on shared infrastructure, but they do **not** grant authorization. When a target is fronted by a CDN/WAF or hosted on a shared platform, the provider's acceptable-use policy may also apply — confirm scope with the asset owner and, where required, the provider. The developers accept no liability for misuse.

---

## 🔍 What It Does

| Capability | Module | Checks |
|---|---|---|
| **Network Scan** | `network_scanner.py` | Nmap (`--top-ports 1000` by default; custom ranges via `-p`) + `vulners` NSE + `-sV`. Port discovery, service/version detection, CVE correlation. HTTP-speaking ports are located by `-sV` and passed to the web vector |
| **Web App Audit** | `web_scanner.py` | HTTP security headers, TLS analysis, technology fingerprinting, directory/sensitive-path enumeration on the detected HTTP port, robots.txt/sitemap review, redirect checks |
| **Nuclei Templates** | `nuclei_scanner.py` | Template-based checks with a configurable rate limit; skipped gracefully if the binary is absent |
| **DNS / Email Security** | `web_scanner.py` (`DNSScanner`) | SPF and DMARC records, policy strength and email-spoofing exposure |
| **Subdomain Recon** | `subdomain_scanner.py` | Certificate-transparency enumeration + DNS brute force and dangling-CNAME takeover detection (no takeover attempted) |
| **API Security** | `api_scanner.py` | Swagger/OpenAPI and GraphQL discovery, HTTP verb probing, JWT weaknesses, rate-limit smoke test and common API misconfigurations |
| **IP Geolocation & Hosting** | `geo_locator.py` | Country/region/city, ISP, organisation, ASN, reverse DNS and web-server details from free GeoIP APIs. Private IPs are never sent externally |
| **Provider Guardrails** | `infrastructure_mapper.py` | CDN/WAF, cloud, PaaS, shared hosting, ISP and private-address classification; passive/throttled modes; RDAP abuse contacts, `security.txt` and suggested ASN pivots |
| **Compliance Mapping** | `compliance_mapper.py` | Deterministic OWASP Top 10 (2021), NIST CSF and PCI-DSS mapping per finding, exposure index and C-level summary |
| **Verify Fix** | `verify_fix.py` | Per-finding, read-only re-test after remediation: fixed / still present / inconclusive / skipped |
| **Exploit likelihood** | `threat_intel.py` | EPSS + CISA KEV enrichment (local 24h cache); deterministic priority, never changes severity |
| **Cookie / CORS / CSP / CSRF** | `web_scanner.py` | Cookie flags, CORS reflection/wildcard, CSP directive review, CSRF token heuristics |
| **Attack path graph** | `attack_path.py` | Deterministic asset → service → finding → impact graph with chokepoints |
| **Findings Engine** | `findings.py`, `scoring.py` | Normalization, deduplication, CVSS/severity, remediation playbooks, MITRE ATT&CK guidance |
| **Evidence Store** | `evidence.py` | Raw tool output per scan (`evidence/<scan_id>/`) so findings are reproducible |
| **AI Reporting** | `ai_engine.py` | Executive summary, per-finding impact, prioritized remediation and compliance narrative from a local SLM |
| **AI Verification** | `verification.py` | Matches every structured AI claim to a real finding, drops ungrounded claims and stamps a SHA-256 provenance record |
| **PDF Report** | `report_gen.py` | Branded report: `SmartVAPT_<scan_id>.pdf`, including Sections L (infrastructure/guardrails) and M (compliance) |
| **Exports** | `exporters.py` | JSON, HTML dashboard and SARIF 2.1.0 |

### Sample output from a real run

Quick web + DNS scan (`--no-network --no-nuclei`), 17 Nov 2026:

```
Scan ID  : 20261117_145220
Target   : scanme.nmap.org
Provider : Linode / Akamai Cloud (Cloud infrastructure) · mode: standard
Findings : 7 total → 2 high / 5 medium
DNS      : Missing SPF record, Missing DMARC record
Web      : 5 missing security headers
Compliance: 70/100 (Critical) · 7 mapped findings
Report   : SmartVAPT_20261117_145220.pdf (10 pages, Sections L/M)
Elapsed  : ~42 s
```

CDN/WAF smoke run (`cloudflare.com`): classified **Cloudflare (CDN / WAF) → passive mode**, active checks skipped, abuse contacts and `security.txt` collected, report generated in ~42 s.

---

## 🤖 AI-Powered Reports (Local Small Language Model)

The PDF can be enriched with an **executive summary, per-finding impact analysis, a prioritized remediation roadmap and a compliance narrative** generated by a *local* small language model. All analysis runs on your machine — scan data never leaves it.

1. Install [Ollama](https://ollama.com) and pull a small model:
   ```bash
   ollama pull phi3:mini
   ```
   Other good options: `gemma2:2b`, `llama3.2:3b`, `qwen2.5:3b`.
2. Keep the server running:
   ```bash
   ollama serve
   ```
3. Optional overrides:
   ```bash
   export SLM_MODEL="phi3:mini"
   export SLM_BASE_URL="http://localhost:11434"
   export SLM_PROVIDER="ollama"
   ```
4. Launch SmartVAPT:
   ```bash
   streamlit run main.py
   ```

The sidebar shows **🟢 AI ready**, **🟡 AI model missing** or **🔴 AI offline**. After a scan, a banner states whether the narrative came from the model or the deterministic fallback. Without a running SLM the tool still works fully and the PDF is still generated.

### AI Output Verification (Grounding)

Every structured AI claim is verified against the actual scan findings before it reaches the report:

- The SLM must return a `finding_id` copied verbatim from the scan findings.
- `verification.py` matches the claim to a real finding (exact ID → exact title → fuzzy title ≥ 85%).
- **Ungrounded claims are dropped**; severity mismatches are corrected to the scan value.
- Numeric severity claims in the executive summary are checked against real counts.
- PDF/JSON/HTML/SARIF carry a provenance stamp: scan ID, finding count and a SHA-256 digest of the findings.

This keeps the structured report data traceable to SmartVAPT's own results.

---

## 🛡️ Provider-Aware Scan Guardrails

`infrastructure_mapper.py` turns the hosting lookup into scan behaviour:

| Detected provider | Behaviour |
|---|---|
| **CDN / WAF** — Cloudflare, Akamai edge, CloudFront, Fastly, Imperva, Sucuri, Azure Front Door, … | **Passive mode.** Network/Nuclei/directory/sensitive-path/API active checks are skipped to avoid WAF bans and to stop treating edge IPs as the client origin. Web headers, TLS, DNS and subdomain recon still run |
| **Shared hosting** — GoDaddy, HostGator, Bluehost, Hostinger, Namecheap, … | **Throttled mode.** Nuclei ≤ 5 req/s, gobuster ≤ 3 threads, request delays, plus a shared-tenant legal warning |
| **PaaS / serverless** — Vercel, Netlify, Heroku, Render, Fly.io, GitHub Pages, … | OS/kernel CVE scanning is disabled; application and API checks stay enabled |
| **Cloud** — AWS, Azure, GCP, DigitalOcean, Linode, Vultr, Hetzner, … | Standard mode plus cloud-specific focus (object storage, IMDS, IAM, ingress) |
| **Unknown / ISP / private** | Standard mode with bounded rates |

The mapper also collects public **RDAP abuse contacts**, the target's **`security.txt`** and **candidate pivot prefixes** (resolved /24s or /48s, plus BGPView ASN prefixes). Pivots are **suggestions only** — SmartVAPT never scans them automatically.

A sidebar checkbox can **override the guardrails** for an explicitly authorized CDN/shared-host test. The override keeps concurrency and request rates low, and the report records that it was used.

---

## 🧭 Compliance Mapping (OWASP / NIST / PCI-DSS)

Every finding is mapped deterministically — never guessed by the SLM — to:

- **OWASP Top 10 (2021)**, including API Security hints from the API scanner
- **NIST CSF** controls (e.g. `PR.AC-4`, `DE.CM-8`)
- **PCI-DSS** requirements (v3.2.1 numbering; validate v4.0 with a QSA)

The **Provider & Compliance** tab and PDF **Section M** show an exposure index (0–100), risk band, per-framework control counts and a C-level narrative. Mappings support remediation planning but are **not a formal audit opinion**.

---

## 🔁 Verify Fix (Per-Finding Re-Test)

**All Findings → Verify Fix** re-runs one read-only check for a selected finding after remediation, without repeating the scan:

| State | Meaning |
|---|---|
| ✅ **Fixed** | The issue is no longer observable (header present, path blocked, port closed, SPF/DMARC published, TLS 1.2+, …) |
| ❌ **Still present** | The issue is still observable |
| ⚠️ **Inconclusive** | The target answered but a definitive verdict was impossible (e.g. soft-404, generic Nuclei finding) |
| ⏭️ **Skipped** | Passive/CDN guardrails are active, or no safe single-request check exists |

Sensitive-file checks validate body signatures (`.env` assignments, `.git/config`, `PRIVATE KEY`, archive magic bytes), so a soft-404 page is reported as inconclusive rather than a false positive. Verify Fix respects provider guardrails and reuses the scan's optional authentication headers. Results are cached per scan and remain available in the **Last scan** view.

---

## 🎛️ Dashboard Controls

### Finding filters (sidebar)
- **Severity filter** — critical/high/medium/low/info
- **Vector filter** — network/web/dns/api/recon
- Applied consistently to the findings list, charts, AI prompt, compliance summary and PDF.

### Report section toggles (sidebar)
- Executive summary / Top findings / Pen-test details & exploitation options / Technical remediation / Appendix
- Each section can be independently enabled or disabled.

### Remediation tracker (sidebar)
- Mark each finding `pending` or `fixed`; choices persist across scans via `st.session_state`.
- Shows `Fixed: X · Pending: Y` to track remediation progress.

### Baseline / diff mode
- Save the current scan as a baseline and compare later runs to highlight new and fixed findings.

---

## 📦 Requirements

- **Kali Linux / Debian / Ubuntu** (recommended; works on other Linux/macOS and Windows)
- Python **3.10+**
- System tools:

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv nmap gobuster dnsutils \
    curl fonts-dejavu-core
```

- **Nuclei** is optional but recommended for template scanning:
  ```bash
  sudo apt install -y nuclei        # or download from ProjectDiscovery
  ```
- PDF generation uses pure-Python `fpdf2`; DejaVu fonts are required for proper glyph rendering.

> Debian/Kali now mark the system Python as **externally managed (PEP 668)**. Install Python packages inside the project virtualenv — do not use `pip install --break-system-packages`.

---

## 🚀 Installation

### Option A — Installer (recommended)

```bash
git clone https://github.com/lichenvarghese-cyber/SmartVAPT-team-3.git
cd SmartVAPT-team-3
chmod +x install.sh
./install.sh
```

`install.sh` installs system tools, creates `venv/`, installs `requirements.txt`, sets Nmap capabilities and adds a `smartvapt` alias.

### Option B — Manual

```bash
git clone https://github.com/lichenvarghese-cyber/SmartVAPT-team-3.git
cd SmartVAPT-team-3
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
```

If `python3 -m venv` fails, install the venv package first:

```bash
sudo apt install -y python3-venv python3-pip
```

### Windows / macOS

The Streamlit app and scanners are cross-platform; system tools (Nmap, gobuster, Nuclei) must be installed separately and available on `PATH`. Then:

```bash
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate
pip install -r requirements.txt
python -m streamlit run main.py
```

---

## ▶️ How to Run

```bash
cd ~/SmartVAPT-team-3
source venv/bin/activate
streamlit run main.py
```

Open **http://localhost:8501**. With the installer alias:

```bash
source ~/.bashrc
smartvapt
```

### Using the dashboard

1. Enter a **Target** (IP, domain or URL).
2. Choose the core vectors:
   - ☑ Network Scan (Nmap + vulners)
   - ☑ Web App Audit (headers + dirs)
   - ☑ DNS / Email Security (SPF + DMARC)
3. Leave **IP Geolocation & Hosting Lookup** and **Provider-aware safety guardrails** enabled (default).
4. Choose the port preset (default: the 1000 most-used ports).
5. Optionally enable **Nuclei**, **Subdomain enum**, **API security checks**, baseline mode or authenticated headers.
6. Click **Run SmartVAPT Scan**.
7. Review the eight tabs: **Network, Web, DNS, Recon / API, All Findings, Location, Provider & Compliance, Attack Path**.
8. Use **All Findings → Verify Fix** after remediation, and download the PDF/JSON/HTML/SARIF exports.

### Scan time

| Setup | Typical |
|---|---|
| CDN/WAF passive | 20–60 s |
| Quick (top 100 ports, web, DNS, no Nuclei/subdomains/API) | 1–3 min |
| Default (top 1000 + web + DNS + Nuclei) | 5–15 min |
| Full (adds subdomains + API) | 10–25 min |

The loading page shows a live ETA and learns per-target timings in `eta_history.json`.

### Headless mode

```bash
python run_headless_scan.py <target> [options]
```

| Option | Effect |
|---|---|
| `--ports top100 / 1-1000 / 22,80,443` | Port selection |
| `--no-network` | Skip Nmap |
| `--no-web` | Skip the web audit |
| `--no-dns` | Skip SPF/DMARC |
| `--no-nuclei` | Skip Nuclei |
| `--no-geo` | Skip geolocation/provider classification |
| `--subdomains` | Enable subdomain enumeration |
| `--api` | Enable API checks |
| `--force-active` | Override provider guardrails (authorized targets only) |

Examples:

```bash
python run_headless_scan.py scanme.nmap.org --no-network --no-nuclei
python run_headless_scan.py cloudflare.com --no-network --no-nuclei
```

### Tests

```bash
source venv/bin/activate
python -m pytest -q
```

Current suite: **111 tests** covering finding normalization, scoring, verification, provider guardrails, compliance mapping, PDF sections L/M/N/O, Verify Fix, threat intelligence, web security checks and attack paths.

---

## 🗂️ Project Structure

```
SmartVAPT-team-3/
├── main.py                    # Streamlit dashboard / orchestrator
├── run_headless_scan.py       # Streamlit-free scan pipeline
├── config.py                  # SLM endpoint/model and report branding
├── network_scanner.py         # Nmap + vulners wrapper
├── web_scanner.py             # Web header/TLS/dir checks + DNS scanner
├── nuclei_scanner.py          # Nuclei template wrapper
├── subdomain_scanner.py       # crt.sh + DNS brute force + takeover check
├── api_scanner.py             # Swagger/GraphQL/JWT/rate-limit checks
├── geo_locator.py             # IP geolocation and hosting lookup
├── infrastructure_mapper.py   # Provider guardrails, abuse contacts, pivots
├── compliance_mapper.py       # OWASP/NIST/PCI mapping + exposure summary
├── verify_fix.py              # Per-finding read-only re-test
├── eta_estimator.py           # Live ETA + per-target timing history
├── command_tracker.py         # Background command status
├── portsets.py                # Port preset definitions
├── ai_engine.py               # Local SLM narrative + MITRE ATT&CK mapping
├── verification.py            # AI claim grounding + SHA-256 provenance
├── findings.py                # Finding dataclass + severity normalization
├── scoring.py                 # CVSS, playbooks, compliance enrichment
├── smartvapt_fixes.py         # Ubuntu CVE validation helpers
├── report_gen.py              # PDF report (Sections A–M)
├── exporters.py               # JSON/HTML/SARIF export
├── evidence.py                # Per-scan raw evidence store
├── requirements.txt
├── install.sh                 # Automated Kali setup
├── tests/                     # 90 pytest tests
└── evidence/<scan_id>/        # Raw tool output for every scan
```

---

## 🛡️ Merits / Why SmartVAPT

- **Tri-vector coverage in one pass** — network, web and email/DNS posture assessed together instead of stitching several tools.
- **Provider-aware safety** — passive mode for CDN/WAF, throttling for shared hosting, PaaS-aware scope and abuse/security contacts, so the tool does not blindly hammer third-party infrastructure.
- **Compliance-ready reporting** — deterministic OWASP Top 10, NIST CSF and PCI-DSS mappings with an exposure index and C-level narrative, not AI-invented references.
- **Evidence-first design** — every finding is backed by raw output under `evidence/<scan_id>/`, making reports auditable and reproducible.
- **Closed-loop remediation** — Verify Fix re-tests individual findings and reports fixed / still present / inconclusive.
- **Privacy-preserving AI** — local SLM via Ollama; no API keys and no scan-data egress. Deterministic fallback keeps reports working offline.
- **AI output verification** — every structured claim is matched to a real finding; ungrounded claims are dropped and a SHA-256 digest is embedded.
- **Professional PDF reporting** — severity-ranked, branded reports including MITRE ATT&CK (Section K), infrastructure/guardrails (L), compliance (M), exploit likelihood (N) and attack path (O).
- **Graceful degradation** — missing Nuclei, gobuster, Ollama or API access never crashes a scan; affected vectors are reported clearly.
- **Beginner-friendly, pro-useful** — one-click Streamlit workflow with a modular Python backend that can be scripted or extended.

---

## 🐛 Troubleshooting

| Symptom | Fix |
|---|---|
| `error: externally-managed-environment` | Use the project venv: `python3 -m venv venv && source venv/bin/activate` (never `--break-system-packages`) |
| `streamlit: command not found` | Activate the venv first: `source venv/bin/activate`, then `streamlit run main.py` |
| `python3 -m venv` fails | `sudo apt install -y python3-venv python3-pip` |
| PDF renders with missing glyphs | `sudo apt install fonts-dejavu-core` |
| Nmap results empty on privileged ports | Run as root or `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)` |
| Sidebar shows **🔴 AI offline** | Install/start Ollama, pull a model (`ollama pull phi3:mini`), verify `curl http://localhost:11434/api/tags`, click **Re-check AI engine** |
| Nuclei skipped | `sudo apt install nuclei` or download from ProjectDiscovery — the scan continues without it |
| gobuster step skipped | `sudo apt install gobuster` |
| Active checks skipped / **Passive mode** banner | Target is behind a CDN/WAF. Test the authorized origin, or enable the guardrail override only with written authorization |
| Verify Fix shows **Skipped** | Passive guardrails are active, or the finding type has no safe single-request check |

---

## 📄 License

MIT — see `LICENSE`. Educational and authorized-testing use only.
