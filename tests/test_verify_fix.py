"""Tests for per-finding Verify Fix re-tests (no real network access)."""
import dns.resolver
import requests

import verify_fix
from verify_fix import FixVerifier, classify, _looks_like


class FakeResponse:
    def __init__(self, status=200, headers=None, content=b"", text=None):
        self.status_code = status
        self.headers = headers or {}
        self.content = content
        self.text = text if text is not None else content.decode("utf-8", "replace")


def _finding(**overrides):
    finding = {
        "id": "WEB-001", "vector": "web", "severity": "medium",
        "title": "Missing security header: Content-Security-Policy",
        "description": "", "evidence": "", "target": "https://example.com",
        "port": None, "cve": None,
    }
    finding.update(overrides)
    return finding


def test_classify_supported_findings():
    assert classify(_finding()) == ("header", "Content-Security-Policy")
    assert classify(_finding(title="Missing SPF record", vector="dns",
                             target="example.com"))[0] == "dns_spf"
    assert classify(_finding(title="Missing DMARC record", vector="dns",
                             target="example.com"))[0] == "dns_dmarc"
    assert classify(_finding(title="Sensitive file publicly accessible: /.env")) \
        == ("sensitive_path", ".env")
    assert classify(_finding(title="No HTTP -> HTTPS redirect"))[0] == "http_redirect"
    assert classify(_finding(title="TLS issue: TLS 1.0 enabled"))[0] == "tls"
    assert classify(_finding(title="OpenSSH CVE-2024-6387 on OpenSSH port 22",
                             vector="network", cve="CVE-2024-6387", port=22))[0] == "port"
    assert classify(_finding(title="GraphQL introspection enabled at /graphql"))[0] \
        == "graphql"
    assert classify(_finding(title="Dangerous HTTP methods enabled: ['TRACE']"))[0] \
        == "http_methods"
    assert classify(_finding(title="Public API documentation exposed: /swagger.json"))[0] \
        == "api_docs"


def test_classify_unknown_is_inconclusive_not_guessed():
    kind, _ = classify(_finding(title="Subdomain takeover risk", vector="recon"))
    assert kind in ("http_generic", "unsupported")


def test_passive_guardrails_skip_without_touching_the_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network request must not be made")
    monkeypatch.setattr(requests, "get", boom)
    result = verify_fix.verify_fix(_finding(),
                                   guardrails={"passive_only": True,
                                               "overridden": False})
    assert result["status"] == "skipped"
    assert "passive mode" in result["detail"]


def test_header_check_marks_fixed_when_header_present(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(
        200, {"Content-Security-Policy": "default-src 'self'"}))
    result = FixVerifier(_finding()).run()
    assert result["status"] == "fixed"
    assert result["check"] == "header"
    assert result["observed"]["header"] == "Content-Security-Policy"


def test_header_check_marks_still_present_when_missing(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(
        200, {"Server": "nginx"}))
    result = FixVerifier(_finding()).run()
    assert result["status"] == "still_present"


def test_sensitive_path_fixed_when_blocked(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(403))
    result = FixVerifier(_finding(
        title="Sensitive file publicly accessible: /.env")).run()
    assert result["status"] == "fixed"
    assert result["observed"]["status"] == 403


def test_sensitive_path_still_present_with_matching_signature(monkeypatch):
    body = b"APP_KEY=base64:abc\nDB_PASSWORD=secret\n"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(
        200, {"Content-Type": "text/plain"}, body))
    result = FixVerifier(_finding(
        title="Sensitive file publicly accessible: /.env")).run()
    assert result["status"] == "still_present"


def test_sensitive_path_soft404_is_inconclusive(monkeypatch):
    body = b"<html><body>Page not found</body></html>"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, {}, body))
    result = FixVerifier(_finding(
        title="Sensitive file publicly accessible: /.env")).run()
    assert result["status"] == "inconclusive"


def test_spf_check_fixed_when_record_exists(monkeypatch):
    class Rdata:
        strings = [b"v=spf1 include:_spf.example.com -all"]

    monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **k: [Rdata()])
    result = FixVerifier(_finding(title="Missing SPF record", vector="dns",
                                  target="example.com")).run()
    assert result["status"] == "fixed"


def test_dmarc_weak_policy_is_still_present(monkeypatch):
    class Rdata:
        strings = [b"v=DMARC1; p=none; rua=mailto:dmarc@example.com"]

    monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **k: [Rdata()])
    result = FixVerifier(_finding(title="Weak DMARC policy (p=none)",
                                  vector="dns", target="example.com")).run()
    assert result["status"] == "still_present"


def test_redirect_check_fixed_when_https_redirect_present(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(
        301, {"Location": "https://example.com/"}))
    result = FixVerifier(_finding(title="No HTTP -> HTTPS redirect",
                                  target="http://example.com")).run()
    assert result["status"] == "fixed"


def test_content_signatures_avoid_false_positives():
    assert _looks_like(".env", b"DB_HOST=localhost\n") is True
    assert _looks_like(".env", b"<html>not found</html>") is False
    assert _looks_like("id_rsa", b"-----BEGIN PRIVATE KEY-----") is True
    assert _looks_like(".git/config", b"[core]\n\trepositoryformatversion = 0") is True
    assert _looks_like(".htpasswd", b"admin:$apr1$abc$def") is True


def test_unsupported_finding_returns_inconclusive():
    result = FixVerifier(_finding(title="Nuclei: Something (CVE-2020-0001)",
                                  vector="other")).run()
    assert result["status"] == "inconclusive"
    assert result["check"] == "unsupported"
    assert result["duration_ms"] >= 0
