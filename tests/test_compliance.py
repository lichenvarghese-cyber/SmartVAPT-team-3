"""Tests for deterministic OWASP/NIST/PCI compliance mapping."""
from compliance_mapper import (CATEGORIES, enrich, map_finding, summarize)
from scoring import enrich_findings


def _finding(**overrides):
    finding = {
        "id": "WEB-001", "vector": "web", "severity": "high",
        "title": "SQL injection in login form",
        "description": "The login parameter is vulnerable to SQL injection.",
        "evidence": "payload returned database error", "owasp": None,
        "cve": None, "target": "https://example.com",
    }
    finding.update(overrides)
    return finding


def test_injection_maps_to_owasp_a03_and_pci_6_5_1():
    mapping = map_finding(_finding())
    assert mapping["category"] == "injection"
    assert "A03:2021" in mapping["owasp"]
    assert "6.5.1" in mapping["pci_dss"]
    assert mapping["mapping_confidence"] == "high"


def test_explicit_owasp_takes_precedence():
    mapping = map_finding(_finding(owasp="A01:2021 - Broken Access Control",
                                   title="Exposed admin panel"))
    assert mapping["category"] == "access_control"
    assert "A01:2021" in mapping["owasp"]
    assert "6.5.8" in mapping["pci_dss"]


def test_cve_maps_to_vulnerable_components_and_pci_patching():
    mapping = map_finding(_finding(vector="network", title="OpenSSH CVE",
                                   description="Banner matches CVE-2024-6387",
                                   cve="CVE-2024-6387", severity="critical"))
    assert mapping["category"] == "vulnerable_components"
    assert "A06:2021" in mapping["owasp"]
    assert "6.2" in mapping["pci_dss"]
    assert "11.2.1" in mapping["pci_dss"]


def test_enrich_attaches_compliance_and_risk_weight():
    finding = _finding(severity="critical")
    enrich(finding)
    assert finding["compliance"]["category"] == "injection"
    assert finding["compliance_risk"] == 25


def test_enrich_findings_from_scoring_attaches_compliance():
    enriched = enrich_findings([_finding()])
    assert enriched[0]["compliance"]["owasp"] == ["A03:2021"]
    assert "remediation_steps" in enriched[0]


def test_summary_counts_frameworks_and_exposure():
    findings = [
        _finding(severity="critical"),
        _finding(id="WEB-002", title="Missing security header",
                 description="Content-Security-Policy is missing",
                 severity="medium"),
    ]
    for finding in findings:
        enrich(finding)
    summary = summarize(findings)
    assert summary["mapped_findings"] == 2
    assert summary["total_findings"] == 2
    assert summary["exposure_index"] == 33  # 25 (critical) + 8 (medium)
    assert summary["risk_band"] == "Moderate"
    assert summary["owasp"]["A03:2021"]["count"] == 1
    assert summary["pci_dss"]["6.5.1"]["count"] == 1
    assert summary["c_level_summary"]
    assert "not a formal audit" in summary["disclaimer"]


def test_summary_is_empty_safe():
    summary = summarize([])
    assert summary["mapped_findings"] == 0
    assert summary["risk_band"] == "None"
    assert summary["owasp"] == {}


def test_all_categories_have_required_framework_fields():
    for name, spec in CATEGORIES.items():
        assert spec["owasp"], name
        assert spec["nist"], name
        assert spec["pci"], name
