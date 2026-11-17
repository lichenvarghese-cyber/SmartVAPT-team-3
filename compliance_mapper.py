"""Deterministic compliance mapping for SmartVAPT findings.

Maps each finding to OWASP Top 10 (2021), NIST CSF 1.1/2.0-style control
references and PCI-DSS requirements. The mapping is intentionally
conservative and deterministic: it never invents a framework reference and a
low-confidence fallback is labelled as such.

The output is used by:
* ``scoring.enrich_findings()`` — attaches ``finding["compliance"]``;
* the Streamlit dashboard — compliance posture tab;
* the PDF report — Section M;
* the local SLM prompt — the model receives the deterministic summary and is
  asked for a C-level narrative (it does not choose the mappings).
"""
from __future__ import annotations

import re
from typing import Any

OWASP_LABELS = {
    "A01:2021": "A01:2021 — Broken Access Control",
    "A02:2021": "A02:2021 — Cryptographic Failures",
    "A03:2021": "A03:2021 — Injection",
    "A04:2021": "A04:2021 — Insecure Design",
    "A05:2021": "A05:2021 — Security Misconfiguration",
    "A06:2021": "A06:2021 — Vulnerable and Outdated Components",
    "A07:2021": "A07:2021 — Identification and Authentication Failures",
    "A08:2021": "A08:2021 — Software and Data Integrity Failures",
    "A09:2021": "A09:2021 — Security Logging and Monitoring Failures",
    "A10:2021": "A10:2021 — Server-Side Request Forgery (SSRF)",
}

# Each category carries a primary mapping. The references are indicative and
# deliberately short; the report includes a disclaimer for auditors.
CATEGORIES: dict[str, dict[str, Any]] = {
    "access_control": {
        "label": "Broken Access Control",
        "owasp": ["A01:2021"],
        "nist": ["PR.AC-3", "PR.AC-4", "PR.DS-5"],
        "pci": ["6.5.8", "6.5.10", "7.1", "7.2"],
    },
    "crypto": {
        "label": "Cryptographic Failures",
        "owasp": ["A02:2021"],
        "nist": ["PR.DS-1", "PR.DS-2", "PR.DS-5"],
        "pci": ["3.4", "4.1", "6.5.3", "6.5.4"],
    },
    "injection": {
        "label": "Injection",
        "owasp": ["A03:2021"],
        "nist": ["PR.DS-5", "PR.IP-2", "DE.CM-4"],
        "pci": ["6.5.1", "6.5.7"],
    },
    "design": {
        "label": "Insecure Design",
        "owasp": ["A04:2021"],
        "nist": ["ID.RA-1", "PR.IP-1", "PR.PT-3"],
        "pci": ["6.5.6"],
    },
    "misconfig": {
        "label": "Security Misconfiguration",
        "owasp": ["A05:2021"],
        "nist": ["PR.AC-3", "PR.IP-1", "PR.PT-3"],
        "pci": ["2.2", "6.5.6"],
    },
    "vulnerable_components": {
        "label": "Vulnerable and Outdated Components",
        "owasp": ["A06:2021"],
        "nist": ["ID.RA-1", "PR.IP-12", "DE.CM-8"],
        "pci": ["6.2", "6.3.1", "11.2.1"],
    },
    "auth": {
        "label": "Identification and Authentication Failures",
        "owasp": ["A07:2021"],
        "nist": ["PR.AC-1", "PR.AC-7", "PR.AA-3"],
        "pci": ["8.2", "8.3", "6.5.10"],
    },
    "integrity": {
        "label": "Software and Data Integrity Failures",
        "owasp": ["A08:2021"],
        "nist": ["PR.DS-6", "PR.DS-7", "PR.IP-2"],
        "pci": ["6.5.6", "11.5"],
    },
    "logging": {
        "label": "Security Logging and Monitoring Failures",
        "owasp": ["A09:2021"],
        "nist": ["DE.AE-2", "DE.CM-1", "DE.CM-7"],
        "pci": ["10.2", "10.4", "10.6"],
    },
    "ssrf": {
        "label": "Server-Side Request Forgery (SSRF)",
        "owasp": ["A10:2021"],
        "nist": ["DE.CM-1", "PR.AC-3", "PR.PT-4"],
        "pci": ["6.5.1", "6.5.6"],
    },
    "email": {
        "label": "Email Authentication / Spoofing",
        "owasp": ["A05:2021"],
        "nist": ["PR.AC-7", "PR.IP-1", "PR.DS-2"],
        "pci": ["6.5.6", "4.1"],
    },
}

# Explicit OWASP identifiers in a finding take precedence over keyword rules.
_OWASP_TO_CATEGORY = {
    "A01": "access_control", "A02": "crypto", "A03": "injection",
    "A04": "design", "A05": "misconfig", "A06": "vulnerable_components",
    "A07": "auth", "A08": "integrity", "A09": "logging", "A10": "ssrf",
    # OWASP API Security Top 10 (2023) hints used by api_scanner.py.
    "API1": "access_control", "API2": "auth", "API3": "access_control",
    "API4": "design", "API5": "access_control", "API6": "design",
    "API7": "ssrf", "API8": "misconfig", "API9": "misconfig",
    "API10": "integrity",
}

# Ordered from most to least specific. The first matching rule wins.
_KEYWORD_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("injection", (
        "sql injection", "sqli", "cross-site scripting", "xss", "command injection",
        "code injection", "ldap injection", "xml external entity", "xxe",
        "template injection", "ssti", "crlf injection", "header injection",
        "injection", "shell injection", "deserialization",
    )),
    ("ssrf", ("ssrf", "server-side request forgery", "server side request forgery")),
    ("auth", (
        "authentication", "auth bypass", "session fixation", "session hijack",
        "weak password", "default credential", "default password", "no mfa",
        "missing mfa", "brute force", "credential stuffing", "jwt", "token",
        "login", "password", "broken authentication",
    )),
    ("access_control", (
        "broken access control", "idor", "bola", "broken object level",
        "authorization", "authorisation", "unauthorized", "unauthorised",
        "privilege escalation", "directory traversal", "path traversal",
        "forced browsing", "missing access control", "admin panel",
        "exposed admin", "access control", "permission",
    )),
    ("crypto", (
        "tls", "ssl", "certificate", "https", "hsts", "encryption", "cipher",
        "cleartext", "plaintext", "weak protocol", "heartbleed", "sweet32",
        "poodle", "cryptographic",
    )),
    ("logging", (
        "logging", "monitoring", "audit log", "log injection", "no logs",
        "insufficient logging",
    )),
    ("integrity", (
        "deserialization", "supply chain", "unsigned", "integrity", "sri",
        "subresource integrity", "dependency confusion",
    )),
    ("email", (
        "spf", "dmarc", "dkim", "email spoofing", "email security",
        "sender policy framework",
    )),
    ("vulnerable_components", (
        "cve-", "outdated", "vulnerable version", "unpatched", "end-of-life",
        "eol", "component", "dependency", "kernel", "openssl", "openssh",
        "apache", "nginx", "vulnerability", "version disclosure",
    )),
    ("design", (
        "rate limit", "rate-limit", "resource consumption", "business logic",
        "insecure design", "mass assignment", "missing rate limiting",
    )),
    ("misconfig", (
        "header", "csp", "x-frame", "content-security-policy", "directory listing",
        "misconfiguration", "debug", "stack trace", "information disclosure",
        "robots", "sitemap", "swagger", "openapi", "graphql", "cors",
        "sensitive file", "sensitive path", "backup", ".git", ".env",
        "server banner", "exposed", "publicly accessible", "default page",
        "http methods", "options",
    )),
)

_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}

_DISCLAIMER = (
    "Compliance mappings are indicative and support remediation planning; "
    "they are not a formal audit opinion. PCI-DSS references use v3.2.1 "
    "requirement numbering — validate against the applicable v4.0 requirements "
    "with a QSA."
)


def _explicit_category(owasp: str) -> str | None:
    text = str(owasp or "").upper()
    match = re.search(r"\bA(?:PI)?\s*(\d{1,2})\b", text)
    if not match:
        return None
    key = f"A{int(match.group(1)):02d}"
    if "API" in text:
        key = f"API{int(match.group(1))}"
    return _OWASP_TO_CATEGORY.get(key)


def _infer_category(finding: dict[str, Any]) -> tuple[str, str]:
    """Return ``(category, confidence)`` for a finding."""
    explicit = _explicit_category(finding.get("owasp"))
    if explicit:
        return explicit, "high"

    text = " ".join(str(finding.get(k) or "") for k in
                    ("title", "description", "evidence", "service",
                     "cve_note", "remediation")).lower()
    for category, keywords in _KEYWORD_RULES:
        if any(keyword in text for keyword in keywords):
            return category, "high" if len(text) > 20 else "medium"

    vector = str(finding.get("vector") or "").lower()
    if vector == "dns":
        return "email", "medium"
    if vector == "network":
        if finding.get("cve"):
            return "vulnerable_components", "high"
        return "misconfig", "medium"
    if vector in ("api", "web"):
        return "misconfig", "low"
    if vector == "recon":
        return "misconfig", "low"
    if vector == "cloud":
        return "misconfig", "medium"
    return "misconfig", "low"


def map_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Map one finding to OWASP/NIST/PCI references.

    The result is embedded in the finding dict under ``compliance`` so all
    exporters and UI views see the same deterministic mapping.
    """
    finding = finding if isinstance(finding, dict) else {}
    category, confidence = _infer_category(finding)
    spec = CATEGORIES.get(category, CATEGORIES["misconfig"])
    severity = str(finding.get("severity") or "info").lower()
    return {
        "category": category,
        "label": spec["label"],
        "owasp": list(spec["owasp"]),
        "owasp_labels": [OWASP_LABELS.get(code, code) for code in spec["owasp"]],
        "nist_csf": list(spec["nist"]),
        "pci_dss": list(spec["pci"]),
        "mapping_confidence": confidence,
        "risk_weight": _WEIGHTS.get(severity, 1),
    }


def enrich(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach compliance fields to a finding (mutates and returns it)."""
    mapping = map_finding(finding)
    finding["compliance"] = mapping
    finding["compliance_risk"] = mapping["risk_weight"]
    return finding


def _bucket_add(bucket: dict[str, dict[str, Any]], key: str, finding: dict,
                weight: int) -> None:
    item = bucket.setdefault(key, {
        "count": 0, "weight": 0, "severities": {},
        "labels": set(),
    })
    item["count"] += 1
    item["weight"] += weight
    severity = str(finding.get("severity") or "info").lower()
    item["severities"][severity] = item["severities"].get(severity, 0) + 1
    label = (finding.get("compliance") or {}).get("label")
    if label:
        item["labels"].add(label)


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a framework-level compliance posture summary."""
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    owasp: dict[str, dict[str, Any]] = {}
    nist: dict[str, dict[str, Any]] = {}
    pci: dict[str, dict[str, Any]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    exposure = 0
    mapped = 0

    for finding in findings:
        compliance = finding.get("compliance")
        if not isinstance(compliance, dict):
            compliance = map_finding(finding)
        severity = str(finding.get("severity") or "info").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        weight = int(compliance.get("risk_weight") or _WEIGHTS.get(severity, 1))
        exposure += weight
        mapped += 1
        for code in compliance.get("owasp") or []:
            _bucket_add(owasp, code, finding, weight)
        for control in compliance.get("nist_csf") or []:
            _bucket_add(nist, control, finding, weight)
        for req in compliance.get("pci_dss") or []:
            _bucket_add(pci, req, finding, weight)

    def finalize(bucket: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for key, item in bucket.items():
            out[key] = {
                "count": item["count"],
                "weight": item["weight"],
                "severities": dict(item["severities"]),
                "labels": sorted(item["labels"]),
            }
        return dict(sorted(out.items(),
                           key=lambda kv: (-kv[1]["weight"], kv[0])))

    owasp = finalize(owasp)
    nist = finalize(nist)
    pci = finalize(pci)
    risk_index = min(100, exposure)
    if risk_index >= 70:
        risk_band = "Critical"
    elif risk_index >= 40:
        risk_band = "High"
    elif risk_index >= 15:
        risk_band = "Moderate"
    elif risk_index > 0:
        risk_band = "Low"
    else:
        risk_band = "None"

    top_owasp = list(owasp.items())[:3]
    top_pci = list(pci.items())[:5]
    top_nist = list(nist.items())[:5]
    critical_high = severity_counts["critical"] + severity_counts["high"]
    if mapped:
        owasp_text = (f"The largest concentration is {top_owasp[0][1]['labels'][0]} "
                      f"({top_owasp[0][0]}) with {top_owasp[0][1]['count']} finding(s)"
                      if top_owasp and top_owasp[0][1].get("labels") else
                      "OWASP Top 10 exposure is distributed across the assessed surface")
        pci_text = (f" PCI-DSS requirement {top_pci[0][0]} is the most affected control "
                    f"({top_pci[0][1]['count']} finding(s))"
                    if top_pci else " no PCI-DSS controls were implicated")
        c_level = (
            f"The assessment identified {mapped} finding(s) with compliance "
            f"relevance, including {critical_high} critical/high issue(s). "
            f"{owasp_text}.{pci_text}. The compliance exposure index is "
            f"{risk_index}/100 ({risk_band}). Remediation should prioritise the "
            "critical/high findings mapped to the most affected controls before "
            "the next audit or customer security review."
        )
    else:
        c_level = ("No findings were available to map to compliance frameworks. "
                   "Run the assessment with the relevant vectors enabled, then "
                   "review this section before an audit.")

    return {
        "mapped_findings": mapped,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "exposure_index": risk_index,
        "risk_band": risk_band,
        "owasp": owasp,
        "nist_csf": nist,
        "pci_dss": pci,
        "top_owasp": [{"id": k, **v} for k, v in top_owasp],
        "top_pci": [{"id": k, **v} for k, v in top_pci],
        "top_nist": [{"id": k, **v} for k, v in top_nist],
        "c_level_summary": c_level,
        "disclaimer": _DISCLAIMER,
    }


def compliance_rows(summary: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    """Flatten a framework bucket into rows for Streamlit/DataFrame views."""
    bucket = (summary or {}).get(framework) or {}
    rows = []
    for key, item in bucket.items():
        rows.append({
            "reference": key,
            "findings": item.get("count", 0),
            "risk_weight": item.get("weight", 0),
            "critical": (item.get("severities") or {}).get("critical", 0),
            "high": (item.get("severities") or {}).get("high", 0),
            "medium": (item.get("severities") or {}).get("medium", 0),
            "low": (item.get("severities") or {}).get("low", 0),
        })
    return rows
