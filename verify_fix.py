"""Per-finding "Verify Fix" re-tests.

Re-runs one narrow, read-only check for a finding so an assessor can confirm a
remediation without repeating the whole scan. Nothing here exploits a target:
checks are single GET/HEAD/OPTIONS requests, one DNS lookup, one TLS handshake
or one TCP connect.

Status semantics
----------------
``fixed``          the issue is no longer observable
``still_present``  the issue is still observable
``inconclusive``   the target answered but a definitive verdict was impossible
``skipped``        guardrails/unsupported finding type; nothing was sent

Supported checks: security headers, sensitive paths/files (with content
signature validation), TLS/certificate, SPF/DMARC, open ports/CVEs, GraphQL
introspection, HTTP verbs, HTTP->HTTPS redirect and exposed API docs. Other
findings return ``inconclusive`` rather than a guessed verdict.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

USER_AGENT = "SmartVAPT-VerifyFix/1.0 (+authorized-security-testing)"
SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy"]
REDIRECT_CODES = {301, 302, 303, 307, 308}
BLOCKED_CODES = {401, 403, 404, 410}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_header(title: str) -> str | None:
    text = str(title or "").lower()
    for header in SECURITY_HEADERS:
        if header.lower() in text:
            return header
    if "security header" in text and ":" in text:
        return title.split(":", 1)[1].strip()
    return None


def _extract_path(title: str) -> str:
    text = str(title or "")
    match = re.search(r"(?:path|file)[^:]*:\s*/?([^\s,;]+)", text, re.IGNORECASE)
    if match:
        return match.group(1).strip().lstrip("/")
    match = re.search(r"(/[A-Za-z0-9_./-]{2,})", text)
    return match.group(1).strip().lstrip("/") if match else ""


def _origin(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    parsed = urlparse(text)
    if not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _host(target: str) -> str:
    text = str(target or "").strip()
    if "://" not in text:
        text = "https://" + text
    try:
        return urlparse(text).hostname or ""
    except ValueError:
        return ""


def _domain(target: str) -> str:
    host = _host(target)
    if not host:
        return str(target or "").strip().strip(".")
    return host


def classify(finding: dict[str, Any]) -> tuple[str, str]:
    """Return ``(check_kind, parameter)`` for a finding."""
    finding = finding if isinstance(finding, dict) else {}
    title = str(finding.get("title") or "")
    low = title.lower()
    vector = str(finding.get("vector") or "").lower()

    header = _find_header(title)
    if header:
        return "header", header
    if "spf" in low:
        return "dns_spf", ""
    if "dmarc" in low:
        return "dns_dmarc", ""
    if "tls" in low or "ssl" in low or "certificate" in low:
        return "tls", ""
    if "sensitive path" in low or "sensitive file" in low:
        return "sensitive_path", _extract_path(title)
    if "redirect" in low and "https" in low:
        return "http_redirect", ""
    if "graphql" in low and "introspection" in low:
        return "graphql", ""
    if "http methods" in low or "http verbs" in low:
        return "http_methods", ""
    if "api documentation" in low or "swagger" in low or "openapi" in low:
        return "api_docs", ""
    if finding.get("cve") and finding.get("port"):
        return "port", str(finding.get("port"))
    if vector == "network" and finding.get("port"):
        return "port", str(finding.get("port"))
    if vector in ("web", "api", "recon"):
        return "http_generic", ""
    return "unsupported", ""


# ---------------------------------------------------------------------------
# content signatures (avoid treating a soft-404 page as a real secret file)
# ---------------------------------------------------------------------------
def _looks_like(path: str, body: bytes) -> bool | None:
    """Return True/False when a signature is known, None when uncertain."""
    path = str(path or "").lower()
    head = body[:4096]
    if path.endswith((".zip",)):
        return head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06")
    if path.endswith((".gz", ".tar.gz")):
        return head.startswith(b"\x1f\x8b")
    if path.endswith(".sql"):
        upper = head.upper()
        return any(marker in upper for marker in
                   (b"CREATE TABLE", b"INSERT INTO", b"DROP TABLE", b"-- MYSQL"))
    if path.endswith((".bak", ".old", ".php.bak")):
        return b"<?php" in head.lower() or b"db_" in head.lower()
    if path.endswith(".env"):
        return bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", head))
    if path.endswith(".git/config"):
        return b"[core]" in head.lower() or b"repositoryformatversion" in head.lower()
    if path.endswith("id_rsa") or path.endswith("id_dsa"):
        return b"PRIVATE KEY" in head
    if path.endswith(".aws/credentials"):
        return b"aws_access_key_id" in head.lower()
    if path.endswith(".htpasswd"):
        return (b":" in head and any(marker in head for marker in
                                    (b"$apr1$", b"$2y$", b"$2b$", b"{SHA}")))
    return None


class FixVerifier:
    def __init__(self, finding: dict[str, Any], scan_target: str = "",
                 timeout: int = 8,
                 auth_headers: dict[str, str] | None = None):
        self.finding = finding if isinstance(finding, dict) else {}
        self.scan_target = scan_target or ""
        self.timeout = max(2, int(timeout))
        self.auth_headers = dict(auth_headers or {})

    # -- helpers ---------------------------------------------------------
    def _url(self) -> str:
        target = self.finding.get("target") or self.scan_target
        return _origin(target)

    def _headers(self) -> dict[str, str] | None:
        headers = dict(self.auth_headers)
        headers.setdefault("User-Agent", USER_AGENT)
        return headers

    def _result(self, kind: str, status: str, detail: str,
                observed: Any = None, url: str = "") -> dict[str, Any]:
        return {
            "finding_id": self.finding.get("id", ""),
            "title": self.finding.get("title", ""),
            "check": kind,
            "status": status,
            "detail": detail,
            "observed": observed,
            "url": url or self._url(),
            "checked_at": _now(),
        }

    # -- checks ----------------------------------------------------------
    def _check_header(self, header: str) -> dict[str, Any]:
        url = self._url()
        if not url:
            return self._result("header", "inconclusive", "No HTTP target available.")
        r = requests.get(url, timeout=self.timeout, allow_redirects=True,
                         headers=self._headers())
        lowered = {k.lower(): v for k, v in r.headers.items()}
        present = header.lower() in lowered
        return self._result(
            "header", "fixed" if present else "still_present",
            (f"'{header}' is now present ({lowered.get(header.lower(), '')[:80]})."
             if present else f"'{header}' is still missing on {url}."),
            observed={"status": r.status_code, "header": header,
                      "value": lowered.get(header.lower())},
            url=url)

    def _check_sensitive_path(self, path: str) -> dict[str, Any]:
        base = self._url()
        if not base or not path:
            return self._result("sensitive_path", "inconclusive",
                                "Could not determine the path to re-test.")
        url = base.rstrip("/") + "/" + path.lstrip("/")
        r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                         headers=self._headers())
        if r.status_code in BLOCKED_CODES:
            return self._result(
                "sensitive_path", "fixed",
                f"/{path} now returns HTTP {r.status_code}.",
                observed={"status": r.status_code}, url=url)
        if r.status_code not in (200, 206):
            return self._result(
                "sensitive_path", "inconclusive",
                f"/{path} returned HTTP {r.status_code}; verify manually.",
                observed={"status": r.status_code}, url=url)
        verdict = _looks_like(path, r.content)
        if verdict is True:
            status, detail = "still_present", (
                f"/{path} is still readable and matches the expected file "
                f"signature (HTTP {r.status_code}, {len(r.content)} bytes).")
        elif verdict is False:
            status, detail = "inconclusive", (
                f"/{path} returns HTTP 200 but the body no longer matches the "
                "expected file signature — likely a soft-404/placeholder.")
        else:
            status, detail = "inconclusive", (
                f"/{path} returns HTTP 200 ({len(r.content)} bytes); no content "
                "signature is available for this file type, confirm manually.")
        return self._result("sensitive_path", status, detail,
                            observed={"status": r.status_code,
                                      "size": len(r.content),
                                      "content_type": r.headers.get("Content-Type"),
                                      "signature_match": verdict},
                            url=url)

    def _check_dns(self, which: str) -> dict[str, Any]:
        domain = _domain(self.finding.get("target") or self.scan_target)
        if not domain:
            return self._result(which, "inconclusive", "No domain to re-test.")
        try:
            import dns.resolver
            name = domain if which == "dns_spf" else f"_dmarc.{domain}"
            records = [b"".join(rdata.strings).decode("utf-8", "replace")
                       for rdata in dns.resolver.resolve(name, "TXT")]
        except Exception as exc:
            return self._result(which, "still_present",
                                f"No DNS TXT record could be retrieved for "
                                f"{domain} ({exc}).",
                                observed={"error": str(exc)})
        if which == "dns_spf":
            present = any("v=spf1" in rec.lower() for rec in records)
            return self._result(
                "dns_spf", "fixed" if present else "still_present",
                ("SPF record is now published." if present
                 else "No v=spf1 TXT record found."),
                observed={"records": records})
        dmarc = next((rec for rec in records if "v=dmarc1" in rec.lower()), "")
        if not dmarc:
            return self._result("dns_dmarc", "still_present",
                                "No DMARC record found.",
                                observed={"records": records})
        policy = re.search(r"p\s*=\s*(\w+)", dmarc, re.IGNORECASE)
        policy_value = policy.group(1).lower() if policy else "none"
        weak = "weak" in str(self.finding.get("title") or "").lower()
        status = "still_present" if (weak and policy_value == "none") else "fixed"
        detail = (f"DMARC is published with p={policy_value}."
                  if status == "fixed" else "DMARC is still p=none (not enforcing).")
        return self._result("dns_dmarc", status, detail,
                            observed={"record": dmarc, "policy": policy_value})

    def _check_tls(self) -> dict[str, Any]:
        host = _host(self.finding.get("target") or self.scan_target)
        if not host:
            return self._result("tls", "inconclusive", "No host for a TLS check.")
        port = int(self.finding.get("port") or 443)
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    version = tls.version() or ""
                    cert = tls.getpeercert() or {}
        except ssl.SSLCertVerificationError as exc:
            return self._result("tls", "still_present",
                                f"TLS certificate validation failed: {exc}",
                                observed={"error": str(exc)})
        except (OSError, ssl.SSLError) as exc:
            return self._result("tls", "inconclusive",
                                f"TLS handshake could not be completed: {exc}",
                                observed={"error": str(exc)})
        strong = version in ("TLSv1.2", "TLSv1.3")
        detail = (f"Negotiated {version} with a valid certificate."
                  if strong else f"Server negotiated {version or 'unknown'}.")
        return self._result("tls", "fixed" if strong else "still_present",
                            detail, observed={"version": version,
                                              "not_after": cert.get("notAfter")})

    def _check_port(self, port: str) -> dict[str, Any]:
        host = _host(self.finding.get("target") or self.scan_target)
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            return self._result("port", "inconclusive", "Invalid port number.")
        try:
            with socket.create_connection((host, port_number), timeout=self.timeout):
                pass
        except ConnectionRefusedError:
            return self._result("port", "fixed",
                                f"TCP {host}:{port_number} now refuses connections.",
                                observed={"host": host, "port": port_number})
        except (socket.timeout, TimeoutError):
            return self._result("port", "inconclusive",
                                f"TCP {host}:{port_number} timed out (filtered?).",
                                observed={"host": host, "port": port_number})
        except OSError as exc:
            return self._result("port", "inconclusive",
                                f"Connection error: {exc}",
                                observed={"host": host, "port": port_number})
        note = (" Service is still reachable; patch status requires a version "
                "re-check (banner) rather than a port check."
                if self.finding.get("cve") else "")
        return self._result("port", "still_present",
                            f"TCP {host}:{port_number} is still open.{note}",
                            observed={"host": host, "port": port_number})

    def _check_graphql(self) -> dict[str, Any]:
        url = self._url()
        if not url:
            return self._result("graphql", "inconclusive", "No HTTP target available.")
        endpoint = url.rstrip("/") + "/graphql"
        try:
            r = requests.post(endpoint, timeout=self.timeout,
                              json={"query": "{ __schema { types { name } } }"},
                              headers=self._headers())
        except requests.RequestException as exc:
            return self._result("graphql", "inconclusive", f"Request failed: {exc}",
                                url=endpoint)
        enabled = r.status_code == 200 and "__schema" in r.text[:4000]
        return self._result(
            "graphql", "still_present" if enabled else "fixed",
            ("Introspection still returns a schema." if enabled
             else f"Introspection is no longer available (HTTP {r.status_code})."),
            observed={"status": r.status_code}, url=endpoint)

    def _check_http_methods(self) -> dict[str, Any]:
        url = self._url()
        if not url:
            return self._result("http_methods", "inconclusive",
                                "No HTTP target available.")
        r = requests.options(url, timeout=self.timeout, headers=self._headers())
        allow = {v.strip().upper() for v in
                 (r.headers.get("Allow", "") + ","
                  + r.headers.get("Access-Control-Allow-Methods", "")).split(",")
                 if v.strip()}
        dangerous = sorted({"TRACE", "CONNECT", "PUT", "DELETE", "PATCH"} & allow)
        return self._result(
            "http_methods", "still_present" if dangerous else "fixed",
            (f"Server still advertises: {', '.join(dangerous)}." if dangerous
             else "No dangerous methods are advertised on the root resource."),
            observed={"allow": sorted(allow)}, url=url)

    def _check_http_redirect(self) -> dict[str, Any]:
        url = self._url()
        if not url:
            return self._result("http_redirect", "inconclusive",
                                "No HTTP target available.")
        if url.startswith("https://"):
            http_url = "http://" + url[len("https://"):]
        else:
            http_url = url
        r = requests.get(http_url, timeout=self.timeout, allow_redirects=False,
                         headers=self._headers())
        location = r.headers.get("Location", "")
        redirects = r.status_code in REDIRECT_CODES and location.startswith("https://")
        return self._result(
            "http_redirect", "fixed" if redirects else "still_present",
            (f"HTTP now redirects to {location}."
             if redirects else
             f"HTTP returned {r.status_code} without an HTTPS redirect."),
            observed={"status": r.status_code, "location": location},
            url=http_url)

    def _check_api_docs(self) -> dict[str, Any]:
        url = self.finding.get("target") or self._url()
        if not str(url).startswith(("http://", "https://")):
            url = self._url()
        r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                        headers=self._headers())
        if r.status_code in BLOCKED_CODES:
            return self._result("api_docs", "fixed",
                                f"API documentation now returns HTTP {r.status_code}.",
                                observed={"status": r.status_code}, url=url)
        if r.status_code == 200:
            return self._result("api_docs", "still_present",
                                "API documentation is still publicly reachable.",
                                observed={"status": 200}, url=url)
        return self._result("api_docs", "inconclusive",
                            f"API docs returned HTTP {r.status_code}.",
                            observed={"status": r.status_code}, url=url)

    def _check_generic(self) -> dict[str, Any]:
        url = self._url()
        if not url:
            return self._result("http_generic", "inconclusive",
                                "No HTTP target available for a re-test.")
        try:
            r = requests.get(url, timeout=self.timeout, allow_redirects=True,
                             headers=self._headers())
        except requests.RequestException as exc:
            return self._result("http_generic", "inconclusive",
                                f"Target could not be reached: {exc}", url=url)
        return self._result(
            "http_generic", "inconclusive",
            f"Target is reachable (HTTP {r.status_code}), but this finding type "
            "has no deterministic single-request check. Re-run the relevant "
            "scanner or confirm manually.",
            observed={"status": r.status_code}, url=url)

    # -- entry point -----------------------------------------------------
    def run(self, kind: str | None = None, param: str | None = None) -> dict[str, Any]:
        kind, param = (kind, param) if kind else classify(self.finding)
        start = time.perf_counter()
        try:
            if kind == "header":
                out = self._check_header(param)
            elif kind == "sensitive_path":
                out = self._check_sensitive_path(param)
            elif kind in ("dns_spf", "dns_dmarc"):
                out = self._check_dns(kind)
            elif kind == "tls":
                out = self._check_tls()
            elif kind == "port":
                out = self._check_port(param)
            elif kind == "graphql":
                out = self._check_graphql()
            elif kind == "http_methods":
                out = self._check_http_methods()
            elif kind == "http_redirect":
                out = self._check_http_redirect()
            elif kind == "api_docs":
                out = self._check_api_docs()
            elif kind == "unsupported":
                out = self._result(
                    "unsupported", "inconclusive",
                    "This finding type does not have a safe single-request "
                    "re-test. Re-run the relevant scanner after remediation.")
            else:
                out = self._check_generic()
        except requests.RequestException as exc:
            out = self._result(kind, "inconclusive",
                              f"Request failed during re-test: {exc}")
        except Exception as exc:  # never break the dashboard
            out = self._result(kind, "inconclusive", f"Re-test error: {exc}")
        out["duration_ms"] = int((time.perf_counter() - start) * 1000)
        return out


def verify_fix(finding: dict[str, Any], scan_target: str = "",
               guardrails: dict[str, Any] | None = None,
               auth_headers: dict[str, str] | None = None,
               timeout: int = 8) -> dict[str, Any]:
    """Re-test one finding honouring the provider guardrails."""
    guardrails = guardrails if isinstance(guardrails, dict) else {}
    kind, param = classify(finding)
    if guardrails.get("passive_only") and not guardrails.get("overridden"):
        return {
            "finding_id": (finding or {}).get("id", ""),
            "title": (finding or {}).get("title", ""),
            "check": kind,
            "status": "skipped",
            "detail": ("CDN/WAF passive mode is active; targeted re-tests are "
                       "disabled. Override the guardrails only with written "
                       "authorization for this target."),
            "observed": None,
            "url": "",
            "checked_at": _now(),
            "duration_ms": 0,
        }
    return FixVerifier(finding, scan_target=scan_target, timeout=timeout,
                       auth_headers=auth_headers).run(kind, param)
