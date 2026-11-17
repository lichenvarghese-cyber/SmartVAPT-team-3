"""Headless driver that replicates main.py's scan pipeline (Streamlit-free).

Usage: python3 run_headless_scan.py <target> [--ports 1-100] [--no-network] ...
"""
import json
import sys

from ai_engine import AIEngine
from api_scanner import APIScanner
from compliance_mapper import summarize as summarize_compliance
from evidence import EvidenceStore, new_scan_id
from findings import Finding, FindingSet
from geo_locator import GeoLocator
from infrastructure_mapper import (InfrastructureMapper, apply_override,
                                   default_guardrails)
from network_scanner import NetworkScanner
from nuclei_scanner import NucleiScanner
from report_gen import generate_report
from scoring import enrich_findings
from subdomain_scanner import SubdomainScanner
from verification import apply_verification
from web_scanner import DNSScanner, WebScanner


def add_all(fs: FindingSet, items):
    for f in items or []:
        try:
            if isinstance(f, dict):
                fs.add(Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__}))
            else:
                fs.add(f)
        except Exception as fe:
            print(f"  [warn] skipped malformed finding: {fe}")


def main():
    args = sys.argv[1:]
    target = args[0] if args else "scanme.nmap.org"
    ports = "top1000"
    rest = []
    i = 1
    while i < len(args):
        if args[i] == "--ports" and i + 1 < len(args):
            ports = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    # Strip leading dashes so ``--no-network`` matches ``no-network``.
    opts = {a.lower().lstrip("-") for a in rest}
    scan_nuclei = "no-nuclei" not in opts
    scan_network = "no-network" not in opts
    scan_web = "no-web" not in opts
    scan_dns = "no-dns" not in opts
    scan_sub = "subdomains" in opts
    scan_api = "api" in opts
    force_active = "force-active" in opts

    def log(line):
        print(line.rstrip())

    scan_id = new_scan_id()
    evidence = EvidenceStore(scan_id)
    findings = FindingSet()
    results = {"target": target, "scan_id": scan_id}

    # Derived once: web and subdomain steps need these even when the network
    # or DNS scan is disabled (previously raised NameError with
    # --no-network / --no-dns).
    net_target = (target.replace("http://", "").replace("https://", "")
                  .split("/")[0].split(":")[0])
    domain = net_target

    guardrails = default_guardrails(10)
    infrastructure: dict = {}
    if "no-geo" not in opts:
        print("[*] IP Geolocation & Hosting Lookup...")
        try:
            results["geo"] = GeoLocator(target, evidence=evidence).locate()
            print(f"    -> {results['geo'].get('summary') or 'no location data'}")
        except Exception as e:
            results["geo"] = {"error": str(e)}
            print(f"[!] geolocation error: {e}")
        print("[*] Provider classification & guardrails...")
        try:
            infrastructure = InfrastructureMapper(
                target, evidence=evidence).analyze(
                    results["geo"], requested_nuclei_rate=10)
            if force_active:
                infrastructure = apply_override(infrastructure,
                                                requested_nuclei_rate=10)
            results["infrastructure"] = infrastructure
            guardrails = infrastructure.get("guardrails") or guardrails
            print(f"    -> {infrastructure.get('provider_label')} | "
                  f"mode: {infrastructure.get('recommended_mode')}")
            for warning in infrastructure.get("warnings") or []:
                print(f"    [!] {warning}")
        except Exception as e:
            results["infrastructure"] = {"error": str(e)}
            print(f"[!] provider classification error: {e}")
    else:
        results["geo"] = {}
        results["infrastructure"] = {}
    results["guardrails"] = guardrails

    if scan_network and not guardrails.get("allow_network", True):
        results["network"] = {
            "skipped": "provider_guardrail",
            "reason": "Network/OS scanning disabled by provider guardrails.",
        }
        print("[i] network scan skipped by provider guardrails")
    elif scan_network:
        print("[*] Network scan (nmap + vulners)...")
        try:
            ns = NetworkScanner(net_target, evidence=evidence)
            net_result = ns.scan(ports=ports, os_detect=False, progress_cb=log)
            results["network"] = net_result
            results["ports_requested"] = ports
            add_all(findings, net_result.get("findings"))
        except Exception as e:
            results["network"] = {"error": str(e)}
            print(f"[!] network error: {e}")

    http_services = ((results.get("network") or {}).get("http_services") or [])
    if not http_services and scan_web:
        from portsets import probe_http_ports
        http_services = probe_http_ports(net_target)
        if http_services:
            print(f"[i] direct probe found HTTP on port {http_services[0]['port']} -> {http_services[0]['url']}")
    if scan_web:
        print("[*] Web app audit...")
        try:
            ws = WebScanner(target, evidence=evidence)
            if http_services:
                det_url = http_services[0].get("url") or ""
                ws.set_target(det_url,
                              port=http_services[0].get("port"),
                              service=http_services[0].get("service"))
                from urllib.parse import urlparse as _up
                req_port = _up(target if "://" in target else "http://" + target).port
                det_port = _up(det_url).port
                if det_port and det_port not in (req_port, 80, 443):
                    print(f"[i] nmap -sV found HTTP on port {det_port}; web audit re-pointed to {ws.target}")
            web_result = {
                "headers": ws.check_headers(),
                "technologies": ws.detect_technologies(),
                "directories": (ws.gobuster_scan(
                    progress_cb=log, http_services=http_services,
                    threads=guardrails.get("gobuster_threads", 20),
                    delay=guardrails.get("gobuster_delay", ""),
                    passive=not guardrails.get("allow_directory_bruteforce", True))
                    if guardrails.get("allow_directory_bruteforce", True)
                    else {"target": ws.target, "found": [], "findings": [],
                          "skipped": "provider_guardrail",
                          "error": "Directory brute-forcing disabled by provider guardrails."}),
                "tls": ws.analyze_tls(),
                "robots_sitemap": ws.fetch_robots_sitemap(),
                "sensitive_paths": (ws.probe_sensitive_paths(
                    request_delay=guardrails.get("request_delay", 0.0))
                    if guardrails.get("allow_sensitive_paths", True)
                    else {"found": [], "findings": [], "discarded": [],
                          "skipped": "provider_guardrail",
                          "error": "Sensitive-path probing disabled by provider guardrails."}),
                "redirects": ws.analyze_redirects(),
            }
            results["web"] = web_result
            for key in ("headers", "directories", "tls", "robots_sitemap",
                        "sensitive_paths", "redirects"):
                add_all(findings, web_result.get(key, {}).get("findings"))
        except Exception as e:
            results["web"] = {"error": str(e)}
            print(f"[!] web error: {e}")

    if scan_dns:
        print("[*] DNS / email security (SPF/DMARC)...")
        try:
            ds = DNSScanner(domain, evidence=evidence)
            dns_result = ds.check_email_security()
            results["dns"] = dns_result
            add_all(findings, dns_result.get("findings"))
        except Exception as e:
            results["dns"] = {"error": str(e)}
            print(f"[!] dns error: {e}")

    if scan_nuclei and not guardrails.get("allow_nuclei", True):
        results["nuclei"] = {
            "skipped": "provider_guardrail", "available": False,
            "matched": [], "findings": [],
            "error": "Nuclei disabled by provider guardrails (passive mode).",
        }
        print("[i] nuclei skipped by provider guardrails")
    elif scan_nuclei:
        print("[*] Nuclei template scan...")
        try:
            nuc_target = (((results.get("web") or {}).get("directories") or {}).get("target")) \
                or (results.get("network") or {}).get("primary_http_url") or target
            effective_rl = min(10, int(guardrails.get("nuclei_rate_limit", 10)))
            nsc = NucleiScanner(nuc_target, evidence=evidence,
                                rate_limit=effective_rl)
            nuc_result = nsc.scan(progress_cb=log)
            results["nuclei"] = nuc_result
            add_all(findings, nuc_result.get("findings"))
            if not nuc_result.get("available"):
                print(f"[i] nuclei skipped: {nuc_result.get('error')}")
        except Exception as e:
            results["nuclei"] = {"error": str(e)}

    if scan_sub:
        print("[*] Subdomain enumeration...")
        try:
            ssc = SubdomainScanner(domain, evidence=evidence)
            sub_result = ssc.enumerate(progress_cb=log)
            results["subdomains"] = sub_result
            add_all(findings, sub_result.get("findings"))
        except Exception as e:
            results["subdomains"] = {"error": str(e)}

    if scan_api and not guardrails.get("allow_api", True):
        results["api"] = {
            "skipped": "provider_guardrail", "endpoints": [], "findings": [],
            "errors": ["API checks disabled by provider guardrails (passive mode)."],
        }
        print("[i] API checks skipped by provider guardrails")
    elif scan_api:
        print("[*] API security checks...")
        try:
            asc = APIScanner(target, evidence=evidence)
            api_result = asc.run_all(progress_cb=log)
            results["api"] = api_result
            add_all(findings, api_result.get("findings"))
        except Exception as e:
            results["api"] = {"error": str(e)}

    patched_cves, validated_counts = [], {}
    net = results.get("network") or {}
    ssh_banner = ""
    for host in net.get("hosts", []) or []:
        for p in host.get("ports", []) or []:
            if str(p.get("service", "")).lower().startswith("ssh") and p.get("banner"):
                ssh_banner = str(p["banner"])
                break
        if ssh_banner:
            break
    if not ssh_banner:
        lo = net.get("nmap_last_output") or net.get("raw_output") or ""
        for line in str(lo).splitlines():
            if "SSH-" in line and "OpenSSH" in line:
                ssh_banner = line.strip()
                break
    cve_fs = [f for f in findings.list() if getattr(f, "cve", None)]
    if ssh_banner and cve_fs:
        ssh_cve_fs = [f for f in cve_fs if str(f.service or "").lower() == "ssh"]
        print(f"[*] Validating {len(ssh_cve_fs)} SSH CVEs against Ubuntu security data...")
        try:
            import smartvapt_fixes as sf
            dicts = [f.to_dict() for f in ssh_cve_fs]
            buckets = sf.apply_validations(dicts, ssh_banner, service_filter="ssh")
            validated_counts = {k: len(v) for k, v in buckets.items()}
            patched_cves = sorted({f["cve"] for f in buckets["patched"]})
            patched_ids = {id(f) for f in buckets["patched"]}
            for f, d in zip(ssh_cve_fs, dicts):
                if id(d) in patched_ids:
                    findings.remove(f.id)
                else:
                    for attr in ("severity", "confidence", "cve_surface",
                                 "cve_note", "ubuntu_validation",
                                 "severity_downgrade_reason"):
                        if d.get(attr) is not None:
                            setattr(f, attr, d[attr])
            results["ssh_banner"] = ssh_banner
            results["cve_validation"] = {
                "banner": ssh_banner,
                "release": __import__("smartvapt_fixes").ubuntu_release_for_banner(ssh_banner),
                "counts": validated_counts,
                "patched": patched_cves,
            }
            print(f"    -> patched: {validated_counts.get('patched', 0)}, "
                  f"vulnerable: {validated_counts.get('vulnerable', 0)}, "
                  f"unconfirmed: {validated_counts.get('unconfirmed', 0)}")
        except Exception as e:
            print(f"[!] CVE validation skipped: {e}")

    print("[*] Scoring / enrichment...")
    enriched = enrich_findings(findings.to_dict_list())
    results["findings"] = enriched
    results["compliance"] = summarize_compliance(enriched)
    print(f"    -> compliance exposure: "
          f"{results['compliance'].get('exposure_index', 0)}/100 "
          f"({results['compliance'].get('risk_band', 'None')})")

    print("[*] AI analysis (local SLM; falls back if unavailable)...")
    try:
        ai_result = AIEngine().analyze(enriched, results)
    except Exception as e:
        ai_result = {"executive_summary": f"AI unavailable: {e}",
                     "overall_risk": "Unknown", "risk_score": 0,
                     "top_findings": [], "technical_remediation": [],
                     "compliance_summary": "",
                     "conclusion": ""}
    try:
        ai_result = apply_verification(enriched, ai_result, scan_id=scan_id)
        results["verification"] = ai_result.get("verification")
    except Exception as e:
        results["verification"] = {"verified": False, "status": "error",
                                   "error": str(e), "scan_id": scan_id}

    pdf_path = f"SmartVAPT_{scan_id}.pdf"
    print("[*] Generating PDF report...")
    try:
        generate_report(results, ai_result, pdf_path)
    except Exception as e:
        pdf_path = None
        print(f"[!] PDF generation failed: {e}")

    counts = {}
    for f in enriched:
        s = str(f.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1
    print("\n===== SCAN SUMMARY =====")
    print(f"Target   : {target}")
    print(f"Scan ID  : {scan_id}")
    print(f"Findings : {len(enriched)} total -> {counts}")
    net = results.get("network", {})
    if net.get("summary"):
        print(f"Network  : {net['summary']}")
    print(f"Evidence : {evidence.path()}")
    print(f"Report   : {pdf_path}")

    with open(f"results_{scan_id}.json", "w") as fh:
        json.dump({"results": results, "ai": ai_result}, fh, indent=2, default=str)


if __name__ == "__main__":
    main()
