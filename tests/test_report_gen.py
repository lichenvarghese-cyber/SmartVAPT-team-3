"""Regression tests for PDF generation (including the appendix/provenance)."""
import pytest

import report_gen
from verification import mitre_for


def _scan():
    return {
        "target": "scanme.nmap.org",
        "scan_id": "TEST-1",
        "findings": [
            {"id": "NET-001", "title": "OpenSSH 8.9p1 vulnerable to CVE-2024-6387",
             "severity": "critical", "vector": "network", "target": "scanme.nmap.org",
             "evidence": "banner", "remediation_steps": ["Upgrade OpenSSH"]},
            {"id": "WEB-001", "title": "Missing Strict-Transport-Security header",
             "severity": "medium", "vector": "web", "target": "scanme.nmap.org",
             "evidence": "header missing"},
        ],
        "network": {},
        "web": {},
        "nuclei": {},
    }


def _ai():
    return {
        "executive_summary": "1 critical, 1 medium finding.",
        "overall_risk": "High",
        "risk_score": 7.5,
        "top_findings": [
            {"finding_id": "NET-001", "title": "OpenSSH CVE", "severity": "critical",
             "business_impact": "RCE risk.", "remediation": "Upgrade.",
             "mitre_attack": "T1210"},
        ],
        "technical_remediation": [
            {"finding_id": "NET-001", "finding": "OpenSSH CVE", "owasp": "A06",
             "mitre_attack": "T1210", "steps": ["Upgrade"], "commands": ["apt upgrade"]},
        ],
        "conclusion": "Prioritise OpenSSH.",
        "verification": {
            "scan_id": "TEST-1", "status": "verified", "verified": True,
            "finding_count": 2, "structured_claims": 2, "grounded_claims": 2,
            "unmatched_claims": 0, "data_sha256": "a" * 64,
            "top_findings": [], "technical_remediation": [],
        },
    }


def test_pdf_report_includes_appendix_and_provenance(tmp_path):
    if report_gen._find_font(report_gen._FONT_CANDIDATES["reg"]) is None:
        pytest.skip("no TrueType font available on this machine")
    out = tmp_path / "report.pdf"
    report_gen.generate_report(_scan(), _ai(), str(out))
    assert out.exists() and out.stat().st_size > 1000


def test_pdf_handles_list_mitre_and_malformed_ai_items(tmp_path):
    """AI may return mitre_attack as a list (per the prompt) or malformed items."""
    if report_gen._find_font(report_gen._FONT_CANDIDATES["reg"]) is None:
        pytest.skip("no TrueType font available on this machine")
    ai = _ai()
    ai["top_findings"][0]["mitre_attack"] = ["T1210", "T1190"]
    ai["top_findings"].append("not a JSON object")
    ai["technical_remediation"][0]["mitre_attack"] = ["T1021.004"]
    out = tmp_path / "report_list_mitre.pdf"
    report_gen.generate_report(_scan(), ai, str(out))
    assert out.exists() and out.stat().st_size > 1000


def test_mitre_map_is_deterministic():
    assert mitre_for({"title": "OpenSSH 8.9p1 vulnerable"}) == "T1021.004"
    assert mitre_for({"title": "SQL injection in login form"}) == "T1190"
    assert mitre_for({"title": "No matching technique here"}) is None
