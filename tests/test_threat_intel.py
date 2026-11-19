"""Tests for EPSS / CISA KEV enrichment (no real network access)."""
import json

import threat_intel


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _routing_get(url, params=None, **kwargs):
    _routing_get.calls = getattr(_routing_get, "calls", []) + [url]
    if url == threat_intel.KEV_URL:
        return FakeResponse({"vulnerabilities": [
            {"cveID": "CVE-2024-6387", "dateAdded": "2024-07-01",
             "dueDate": "2024-07-22", "knownRansomwareCampaignUse": "Known",
             "vendorProject": "OpenBSD", "product": "OpenSSH",
             "vulnerabilityName": "regreSSHion"},
        ]})
    if url == threat_intel.EPSS_URL:
        return FakeResponse({"data": [
            {"cve": "CVE-2024-6387", "epss": "0.944", "percentile": "0.999"},
            {"cve": "CVE-2020-0001", "epss": "0.02", "percentile": "0.4"},
        ]})
    raise AssertionError(f"unexpected URL {url}")


def _findings():
    return [
        {"id": "NET-001", "cve": "CVE-2024-6387", "severity": "high",
         "title": "OpenSSH regreSSHion"},
        {"id": "NET-002", "cve": "CVE-2020-0001", "severity": "medium",
         "title": "Old CVE"},
        {"id": "WEB-001", "cve": None, "severity": "medium",
         "title": "Missing header"},
    ]


def test_enrich_attaches_epss_and_kev(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_intel.requests, "get", _routing_get)
    _routing_get.calls = []
    findings = _findings()
    summary = threat_intel.enrich_findings(
        findings, cache_path=str(tmp_path / "cache.json"))

    assert findings[0]["kev"] is True
    assert findings[0]["epss"] == 0.944
    assert findings[0]["epss_percentile"] == 0.999
    assert findings[0]["exploit_priority"] == "known_exploited"
    assert findings[0]["kev_date_added"] == "2024-07-01"
    assert findings[1]["kev"] is False
    assert findings[1]["epss"] == 0.02
    assert findings[1]["exploit_priority"] == "low"
    assert "epss" not in findings[2]
    assert summary["cves_checked"] == 2
    assert summary["kev_matches"] == 1
    assert summary["epss_scored"] == 2
    assert summary["errors"] == []


def test_enrich_uses_cache_on_second_run(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_intel.requests, "get", _routing_get)
    _routing_get.calls = []
    cache = str(tmp_path / "cache.json")
    threat_intel.enrich_findings(_findings(), cache_path=cache)
    first = len(_routing_get.calls)
    threat_intel.enrich_findings(_findings(), cache_path=cache)
    assert len(_routing_get.calls) == first


def test_enrich_degrades_gracefully_offline(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise ConnectionError("offline")

    monkeypatch.setattr(threat_intel.requests, "get", boom)
    findings = _findings()
    summary = threat_intel.enrich_findings(
        findings, cache_path=str(tmp_path / "cache.json"))
    assert findings[0]["kev"] is False
    assert findings[0]["epss"] is None
    assert findings[0]["exploit_priority"] == "unknown"
    assert len(summary["errors"]) == 2
    # Original severity is untouched.
    assert findings[0]["severity"] == "high"


def test_no_cves_makes_no_requests(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network must not be used")

    monkeypatch.setattr(threat_intel.requests, "get", boom)
    summary = threat_intel.enrich_findings(
        [{"id": "WEB-001", "cve": None, "title": "header"}],
        cache_path=str(tmp_path / "cache.json"))
    assert summary["source"] == "none"
    assert summary["cves_checked"] == 0


def test_cache_file_is_valid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_intel.requests, "get", _routing_get)
    cache = tmp_path / "cache.json"
    threat_intel.enrich_findings(_findings(), cache_path=str(cache))
    data = json.loads(cache.read_text())
    assert "CVE-2024-6387" in data["kev"]["data"]
    assert data["epss"]["data"]["CVE-2024-6387"]["epss"] == 0.944
