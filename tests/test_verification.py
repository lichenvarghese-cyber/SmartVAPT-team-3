"""Tests for AI-output grounding/provenance verification."""
import verification


def _findings():
    return [
        {"id": "NET-001", "title": "OpenSSH 8.9p1 vulnerable to CVE-2024-6387",
         "severity": "critical", "vector": "network"},
        {"id": "WEB-001", "title": "Missing Strict-Transport-Security header",
         "severity": "medium", "vector": "web"},
    ]


def test_digest_is_deterministic():
    assert verification.findings_digest(_findings()) == \
        verification.findings_digest(list(reversed(_findings())))


def test_match_by_finding_id_and_severity_correction():
    ai = {
        "top_findings": [
            {"finding_id": "NET-001", "title": "OpenSSH 8.9p1 vulnerable",
             "severity": "low"},
        ],
        "technical_remediation": [],
        "executive_summary": "1 critical finding.",
    }
    result = verification.apply_verification(_findings(), ai, scan_id="S1")
    assert result["verification"]["verified"] is True
    assert result["top_findings"][0]["severity"] == "critical"
    assert result["top_findings"][0]["finding_id"] == "NET-001"


def test_unmatched_claim_is_dropped():
    ai = {
        "top_findings": [
            {"finding_id": "FAKE", "title": "Totally invented finding",
             "severity": "critical"},
            {"finding_id": "WEB-001", "title": "Missing HSTS header",
             "severity": "medium"},
        ],
        "technical_remediation": [],
        "executive_summary": "No numeric claims here.",
    }
    result = verification.apply_verification(_findings(), ai, scan_id="S1")
    assert len(result["top_findings"]) == 1
    assert result["top_findings"][0]["finding_id"] == "WEB-001"
    assert result["verification"]["verified"] is False
    assert result["verification"]["unmatched_claims"] == 1


def test_summary_numeric_contradiction_is_flagged():
    ai = {
        "top_findings": [],
        "technical_remediation": [],
        "executive_summary": "The scan found 9 critical and 9 medium issues.",
    }
    result = verification.apply_verification(_findings(), ai, scan_id="S1")
    assert result["verification"]["verified"] is False
    assert result["verification"]["summary_contradictions"]


def test_fuzzy_title_match():
    ai = {
        "top_findings": [
            {"title": "OpenSSH 8.9p1 vulnerable to CVE-2024-6387",
             "severity": "critical"},
        ],
        "technical_remediation": [],
        "executive_summary": "",
    }
    result = verification.apply_verification(_findings(), ai, scan_id="S1")
    assert result["top_findings"][0]["finding_id"] == "NET-001"
    assert result["verification"]["verified"] is True
