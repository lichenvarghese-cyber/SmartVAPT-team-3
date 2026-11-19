"""Tests for cookie/CORS/CSP/CSRF checks (no real network access)."""
import web_scanner
from web_scanner import WebScanner


class FakeHeaderList:
    def __init__(self, values=None):
        self.values = values or {}

    def getlist(self, name):
        return self.values.get(name, [])


class FakeRaw:
    def __init__(self, set_cookies=None):
        self.headers = FakeHeaderList({"Set-Cookie": set_cookies or []})


class FakeResponse:
    def __init__(self, status=200, headers=None, body="", set_cookies=None):
        self.status_code = status
        self.headers = headers or {}
        self.text = body
        self.raw = FakeRaw(set_cookies)


def _scanner():
    return WebScanner("https://example.com")


def test_cookie_flags_are_reported(monkeypatch):
    cookies = ["session=abc; Path=/; HttpOnly",
               "pref=1; Secure; SameSite=Lax"]
    monkeypatch.setattr(web_scanner.requests, "get",
                        lambda *a, **k: FakeResponse(set_cookies=cookies))
    result = _scanner().check_cookies()
    titles = [f["title"] for f in result["findings"]]
    assert any("Secure" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)
    assert len(result["cookies"]) == 2
    assert result["cookies"][0]["httponly"] is True
    assert result["cookies"][1]["secure"] is True


def test_no_cookies_no_findings(monkeypatch):
    monkeypatch.setattr(web_scanner.requests, "get",
                        lambda *a, **k: FakeResponse())
    result = _scanner().check_cookies()
    assert result["findings"] == []
    assert result["cookies"] == []


def test_cors_reflection_with_credentials_is_high(monkeypatch):
    probe = "https://smartvapt-probe.invalid"
    monkeypatch.setattr(web_scanner.requests, "get", lambda *a, **k: FakeResponse(
        headers={"Access-Control-Allow-Origin": probe,
                 "Access-Control-Allow-Credentials": "true"}))
    result = _scanner().check_cors()
    assert result["findings"][0]["severity"] == "high"
    assert "credentials" in result["findings"][0]["title"].lower()


def test_cors_wildcard_without_credentials_is_not_flagged(monkeypatch):
    monkeypatch.setattr(web_scanner.requests, "get", lambda *a, **k: FakeResponse(
        headers={"Access-Control-Allow-Origin": "*"}))
    result = _scanner().check_cors()
    assert result["findings"] == []
    assert result["allow_origin"] == "*"


def test_cors_absent_is_not_flagged(monkeypatch):
    monkeypatch.setattr(web_scanner.requests, "get",
                        lambda *a, **k: FakeResponse())
    assert _scanner().check_cors()["findings"] == []


def test_csp_unsafe_inline_is_flagged(monkeypatch):
    policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    monkeypatch.setattr(web_scanner.requests, "get", lambda *a, **k: FakeResponse(
        headers={"Content-Security-Policy": policy}))
    result = _scanner().analyze_csp()
    assert result["present"] is True
    assert any("unsafe-inline" in issue for issue in result["issues"])
    assert result["findings"][0]["severity"] == "medium"


def test_csp_absent_does_not_duplicate_header_finding(monkeypatch):
    monkeypatch.setattr(web_scanner.requests, "get",
                        lambda *a, **k: FakeResponse())
    result = _scanner().analyze_csp()
    assert result["present"] is False
    assert result["findings"] == []


def test_csrf_flags_post_form_without_token(monkeypatch):
    body = ("<html><body><form method='post' action='/login'>"
            "<input name='user'><input type='hidden' name='next' value='/'>"
            "</form></body></html>")
    monkeypatch.setattr(web_scanner.requests, "get", lambda *a, **k: FakeResponse(
        headers={"Content-Type": "text/html"}, body=body))
    result = _scanner().check_csrf()
    assert result["post_forms"] == 1
    assert result["missing_token"] == 1
    assert result["findings"][0]["severity"] == "medium"
    assert "csrf" in result["findings"][0]["title"].lower()


def test_csrf_accepts_post_form_with_token(monkeypatch):
    body = ("<form method='post' action='/login'>"
            "<input type='hidden' name='csrf_token' value='abc'>"
            "<input name='user'></form>")
    monkeypatch.setattr(web_scanner.requests, "get", lambda *a, **k: FakeResponse(
        headers={"Content-Type": "text/html"}, body=body))
    result = _scanner().check_csrf()
    assert result["post_forms"] == 1
    assert result["missing_token"] == 0
    assert result["findings"] == []


def test_csrf_ignores_get_forms(monkeypatch):
    body = "<form method='get' action='/search'><input name='q'></form>"
    monkeypatch.setattr(web_scanner.requests, "get", lambda *a, **k: FakeResponse(
        headers={"Content-Type": "text/html"}, body=body))
    assert _scanner().check_csrf()["findings"] == []
