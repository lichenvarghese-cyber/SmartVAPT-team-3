"""Provider-aware infrastructure classification and scan guardrails.

This module turns the geolocation/hosting lookup into an actionable profile:

* what kind of provider hosts the target (CDN/WAF, cloud, PaaS, shared host,
  ISP, private address);
* the ASN and public abuse/security contacts (RDAP + ``security.txt``);
* candidate pivot targets (resolved /24s and public BGP prefixes);
* a concrete scanning mode (``passive``, ``throttled`` or ``standard``) plus
  flags consumed by the Streamlit/headless pipelines.

Design notes
------------
* Nothing here ever scans a pivot target. Pivots are *suggestions* only and
  must be authorised separately.
* A CDN/WAF result switches the pipeline to passive mode so we do not hammer
  edge infrastructure, trigger WAF bans, or report CDN IPs as the client's
  origin.
* Shared hosting switches to throttled mode (low concurrency, delays) because
  a noisy scan can affect unrelated tenants.
* PaaS/serverless disables OS-level/network CVE scanning, which is not
  meaningful for a managed runtime, and focuses on the application layer.
* All external lookups fail gracefully. A scan never breaks because RDAP/BGP
  is unreachable.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

import requests

from geo_locator import GeoLocator, _is_private, extract_host

_DEFAULT_TIMEOUT = 6
_USER_AGENT = "SmartVAPT-InfrastructureMapper/1.0 (+authorized-security-testing)"

# ``(display name, type, is_cdn, is_waf, patterns, abuse_contact)``.
# Patterns are matched against organisation / ISP / ASN / reverse DNS / web
# server header / hostname in a case-insensitive way. Order matters: the
# first matching rule wins on equal signal strength.
_PROVIDER_RULES: tuple[tuple[str, str, bool, bool, tuple[str, ...], str], ...] = (
    # ---- CDN / WAF edge providers -------------------------------------
    ("Cloudflare", "cdn_waf", True, True,
     ("cloudflare", "cloudflarenet", "as13335"), "abuse@cloudflare.com"),
    ("Akamai", "cdn_waf", True, True,
     ("akamai", "akamaighost", "as20940", "as16625", "as21342"),
     "abuse@akamai.com"),
    ("Amazon CloudFront", "cdn_waf", True, True,
     ("cloudfront",), "abuse@amazonaws.com"),
    ("Fastly", "cdn_waf", True, False,
     ("fastly", "as54113"), "abuse@fastly.com"),
    ("Imperva / Incapsula", "cdn_waf", True, True,
     ("imperva", "incapsula", "as19551"), "abuse@imperva.com"),
    ("Sucuri", "cdn_waf", True, True,
     ("sucuri", "cloudproxy", "as30148"), "abuse@sucuri.net"),
    ("Azure Front Door", "cdn_waf", True, True,
     ("azure front door", "azurefd", "frontdoor"), "abuse@microsoft.com"),
    ("Google Cloud CDN", "cdn_waf", True, False,
     ("google cloud cdn", "googlecdn"), "abuse@google.com"),
    ("StackPath", "cdn_waf", True, False,
     ("stackpath", "highwinds", "as12989"), "abuse@stackpath.com"),
    ("KeyCDN", "cdn_waf", True, False, ("keycdn",), "abuse@keycdn.com"),
    ("Bunny CDN", "cdn_waf", True, False,
     ("bunnycdn", "bunny.net", "as200325"), "abuse@bunny.net"),
    ("CDN77", "cdn_waf", True, False, ("cdn77",), "abuse@cdn77.com"),
    ("Edgio / Limelight", "cdn_waf", True, False,
     ("edgio", "limelight", "as22822"), "abuse@edgio.com"),
    ("Gcore", "cdn_waf", True, False,
     ("gcore", "as199524"), "abuse@gcore.com"),
    ("Qrator", "cdn_waf", True, True,
     ("qrator", "as197068"), "abuse@qrator.net"),
    # ---- PaaS / managed application platforms -------------------------
    ("Vercel", "paas", False, False,
     ("vercel", "zeit.now", "as16509 vercel"), "abuse@vercel.com"),
    ("Netlify", "paas", False, False,
     ("netlify", "as398101"), "abuse@netlify.com"),
    ("Heroku", "paas", False, False,
     ("heroku", "salesforce", "as40492"), "abuse@heroku.com"),
    ("Render", "paas", False, False, ("render.com", "onrender"), "abuse@render.com"),
    ("Fly.io", "paas", False, False, ("fly.io", "flyio", "as40509"), "abuse@fly.io"),
    ("Railway", "paas", False, False, ("railway.app", "railway"), "abuse@railway.app"),
    ("GitHub Pages", "paas", False, False,
     ("github pages", "github.com", "github.io", "github.net"),
     "abuse@github.com"),
    ("Firebase", "paas", False, False,
     ("firebase", "appspot", "web.app"), "abuse@google.com"),
    ("Azure App Service", "paas", False, False,
     ("azure app service", "azurewebsites"), "abuse@microsoft.com"),
    ("Platform.sh", "paas", False, False,
     ("platform.sh", "platformsh"), "abuse@platform.sh"),
    ("Kinsta", "paas", False, False, ("kinsta",), "abuse@kinsta.com"),
    ("WP Engine", "paas", False, False,
     ("wp engine", "wpengine"), "abuse@wpengine.com"),
    # ---- Shared / budget hosting --------------------------------------
    ("GoDaddy", "shared_hosting", False, False,
     ("godaddy", "as26496", "as32244"), "abuse@godaddy.com"),
    ("HostGator", "shared_hosting", False, False,
     ("hostgator", "as46506"), "abuse@hostgator.com"),
    ("Bluehost", "shared_hosting", False, False,
     ("bluehost", "newfold", "endurance"), "abuse@bluehost.com"),
    ("Hostinger", "shared_hosting", False, False,
     ("hostinger", "as47583"), "abuse@hostinger.com"),
    ("Namecheap", "shared_hosting", False, False,
     ("namecheap", "as22612"), "abuse@namecheap.com"),
    ("DreamHost", "shared_hosting", False, False,
     ("dreamhost", "as26347"), "abuse@dreamhost.com"),
    ("SiteGround", "shared_hosting", False, False,
     ("siteground",), "abuse@siteground.com"),
    ("A2 Hosting", "shared_hosting", False, False,
     ("a2 hosting", "a2hosting"), "abuse@a2hosting.com"),
    ("InMotion Hosting", "shared_hosting", False, False,
     ("inmotion",), "abuse@inmotionhosting.com"),
    ("IONOS / 1&1", "shared_hosting", False, False,
     ("ionos", "1&1", "oneandone", "as8560"), "abuse@ionos.com"),
    ("Network Solutions", "shared_hosting", False, False,
     ("network solutions", "as19871"), "abuse@networksolutions.com"),
    ("HostPapa", "shared_hosting", False, False,
     ("hostpapa",), "abuse@hostpapa.com"),
    ("HostMonster", "shared_hosting", False, False,
     ("hostmonster",), "abuse@hostmonster.com"),
    ("GreenGeeks", "shared_hosting", False, False,
     ("greengeeks",), "abuse@greengeeks.com"),
    ("iPage", "shared_hosting", False, False, ("ipage",), "abuse@ipage.com"),
    ("JustHost", "shared_hosting", False, False,
     ("justhost",), "abuse@justhost.com"),
    ("FatCow", "shared_hosting", False, False, ("fatcow",), "abuse@fatcow.com"),
    # ---- Cloud infrastructure -----------------------------------------
    ("Amazon Web Services", "cloud", False, False,
     ("amazon web services", "amazon.com", "amazon data services",
      "amazon technologies", "aws", "as16509", "as14618", "as8987"),
     "abuse@amazonaws.com"),
    ("Microsoft Azure", "cloud", False, False,
     ("microsoft azure", "microsoft", "azure", "as8075", "as8068"),
     "abuse@microsoft.com"),
    ("Google Cloud", "cloud", False, False,
     ("google cloud", "google llc", "as15169", "as396982"), "abuse@google.com"),
    ("Oracle Cloud", "cloud", False, False,
     ("oracle cloud", "oracle", "as31898"), "abuse@oracle.com"),
    ("IBM Cloud", "cloud", False, False,
     ("ibm cloud", "softlayer", "ibm", "as36351"), "abuse@ibm.com"),
    ("DigitalOcean", "cloud", False, False,
     ("digitalocean", "as14061"), "abuse@digitalocean.com"),
    ("Linode / Akamai Cloud", "cloud", False, False,
     ("linode", "as63949"), "abuse@linode.com"),
    ("Vultr", "cloud", False, False,
     ("vultr", "constant company", "as64515"), "abuse@vultr.com"),
    ("Hetzner", "cloud", False, False,
     ("hetzner", "as24940"), "abuse@hetzner.com"),
    ("OVHcloud", "cloud", False, False,
     ("ovh", "as16276", "as35540"), "abuse@ovh.net"),
    ("Alibaba Cloud", "cloud", False, False,
     ("alibaba", "aliyun", "as45102"), "abuse@alibabacloud.com"),
    ("Tencent Cloud", "cloud", False, False,
     ("tencent", "as132203"), "abuse@tencent.com"),
    ("Scaleway", "cloud", False, False,
     ("scaleway", "online s.a.s.", "as12876"), "abuse@scaleway.com"),
    ("Contabo", "cloud", False, False,
     ("contabo", "as51167"), "abuse@contabo.com"),
    ("Leaseweb", "cloud", False, False,
     ("leaseweb", "as28753", "as60781"), "abuse@leaseweb.com"),
    ("Rackspace", "cloud", False, False,
     ("rackspace", "as19994"), "abuse@rackspace.com"),
)

_TYPE_PRIORITY = {"cdn_waf": 5, "paas": 4, "shared_hosting": 3,
                  "cloud": 2, "isp": 1, "unknown": 0, "private": 0}

# A generic provider match is ignored when a more specific brand is present.
# Example: Linode is now part of Akamai, but a Linode VM is cloud compute, not
# Akamai's CDN/WAF edge; scanning it should not be forced into passive mode.
_PROVIDER_EXCLUSIONS: dict[str, tuple[str, ...]] = {
    "Akamai": ("linode",),
    "Azure Front Door": ("azure app service", "azurewebsites"),
}

PROVIDER_TYPE_LABELS = {
    "cdn_waf": "CDN / WAF",
    "cloud": "Cloud infrastructure",
    "paas": "PaaS / serverless",
    "shared_hosting": "Shared hosting",
    "isp": "ISP / network provider",
    "private": "Private / local address",
    "unknown": "Unknown provider",
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _txt(value: Any) -> str:
    return str(value or "").strip().lower()


def _dedupe(items) -> list[str]:
    out: list[str] = []
    for item in items or []:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _asn_parts(asn: str) -> tuple[str, str]:
    """Split ``AS16509 Amazon.com, Inc.`` into ``('AS16509', 'Amazon.com, Inc.')``."""
    raw = str(asn or "").strip()
    if not raw:
        return "", ""
    match = re.search(r"\bAS\s*(\d{1,12})\b", raw, re.IGNORECASE)
    number = f"AS{match.group(1)}" if match else ""
    name = re.sub(r"^\s*AS\s*\d{1,12}\s*", "", raw).strip(" ,")
    return number, name


def _public_ip(ip: str) -> bool:
    try:
        return not _is_private(ip)
    except Exception:
        return False


def _candidate_prefix(ip: str) -> str | None:
    """Return a conservative pivot prefix for a public IP (/24 or /48)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if _is_private(ip):
        return None
    length = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{length}", strict=False))


# ---------------------------------------------------------------------------
# provider classification (pure, easy to test)
# ---------------------------------------------------------------------------
def _signals(geo: dict[str, Any]) -> list[tuple[str, int]]:
    """Collect (text, weight) signals from a GeoLocator result.

    Weight 3 = web-server header (most direct evidence), 2 = primary
    organisation / ISP / ASN / hostname, 1 = secondary resolved IPs.
    """
    signals: list[tuple[str, int]] = []
    primary = geo.get("primary") or {}
    for field in ("organization", "isp", "asn", "asname", "reverse_dns"):
        value = primary.get(field)
        if value:
            signals.append((str(value), 2))
    hostname = geo.get("hostname") or ""
    if hostname:
        signals.append((str(hostname), 2))
    web_server = (geo.get("web_server") or {}).get("server") or ""
    if web_server:
        signals.append((str(web_server), 3))
    for loc in geo.get("locations") or []:
        if not isinstance(loc, dict) or loc is primary:
            continue
        for field in ("organization", "isp", "asn", "asname", "reverse_dns"):
            value = loc.get(field)
            if value:
                signals.append((str(value), 1))
    return signals


def classify_hosting(geo: dict[str, Any] | None) -> dict[str, Any]:
    """Classify a GeoLocator result into a provider-aware profile.

    The returned dict contains only provider/ASN-level facts; guardrails and
    external intelligence are attached by :class:`InfrastructureMapper`.
    """
    geo = geo if isinstance(geo, dict) else {}
    primary = geo.get("primary") or {}
    hostname = geo.get("hostname") or extract_host(geo.get("target") or "")
    resolved = list(geo.get("resolved_ips") or [])
    is_private = bool(primary.get("private"))
    if resolved:
        is_private = is_private or any(_is_private(ip) for ip in resolved)

    matches: list[dict[str, Any]] = []
    signals = _signals(geo)
    haystacks = [_txt(text) for text, _weight in signals]
    for name, kind, is_cdn, is_waf, patterns, abuse in _PROVIDER_RULES:
        exclusions = _PROVIDER_EXCLUSIONS.get(name, ())
        if any(excl and any(excl in hay for hay in haystacks)
               for excl in exclusions):
            continue
        best_weight = 0
        matched_on = ""
        for text, weight in signals:
            haystack = _txt(text)
            if not haystack:
                continue
            for pattern in patterns:
                if pattern and pattern.lower() in haystack:
                    if weight > best_weight:
                        best_weight = weight
                        matched_on = text
                    break
        if best_weight:
            matches.append({
                "name": name, "type": kind, "cdn": is_cdn, "waf": is_waf,
                "abuse": abuse, "weight": best_weight, "matched_on": matched_on,
            })

    # Strongest signal wins; ties go to the more specific provider type.
    matches.sort(key=lambda m: (m["weight"], _TYPE_PRIORITY.get(m["type"], 0)),
                 reverse=True)
    chosen = matches[0] if matches else None

    cdn_detected = any(m["cdn"] for m in matches)
    waf_detected = any(m["waf"] for m in matches)
    cloud_detected = any(m["type"] == "cloud" for m in matches)
    paas_detected = any(m["type"] == "paas" for m in matches)
    shared_hosting = any(m["type"] == "shared_hosting" for m in matches)

    if is_private:
        provider_type = "private"
        provider_name = "Private / local address"
    elif chosen:
        provider_type = chosen["type"]
        provider_name = chosen["name"]
    else:
        provider_type = "isp" if (primary.get("organization") or primary.get("isp")) else "unknown"
        provider_name = (primary.get("organization") or primary.get("isp")
                         or "Unknown")

    asn_number, as_name = _asn_parts(primary.get("asn") or "")
    return {
        "target": geo.get("target", ""),
        "hostname": hostname,
        "resolved_ips": resolved,
        "private": bool(is_private),
        "provider": provider_name,
        "provider_type": provider_type,
        "provider_type_label": PROVIDER_TYPE_LABELS.get(provider_type, provider_type),
        "provider_matched_on": chosen["matched_on"] if chosen else "",
        "cdn_detected": bool(cdn_detected),
        "waf_detected": bool(waf_detected),
        "cloud_detected": bool(cloud_detected or provider_type == "cloud"),
        "paas_detected": bool(paas_detected or provider_type == "paas"),
        "shared_hosting": bool(shared_hosting or provider_type == "shared_hosting"),
        "asn": asn_number,
        "as_name": as_name,
        "asn_raw": primary.get("asn") or "",
        "abuse_contacts": _dedupe([chosen["abuse"]] if chosen else []),
        "signals": [{"value": v, "weight": w} for v, w in signals],
    }


# ---------------------------------------------------------------------------
# external intelligence (RDAP / BGP / security.txt)
# ---------------------------------------------------------------------------
_RDAP_CACHE: dict[str, list[str]] = {}
_BGP_CACHE: dict[str, list[str]] = {}


def _vcard_emails(entity: dict[str, Any]) -> list[str]:
    emails: list[str] = []
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                value = str(item[3] or "").strip()
                if value and value not in emails:
                    emails.append(value)
    return emails


def _walk_rdap_entities(entity: dict[str, Any], inherited_abuse: bool = False) -> list[str]:
    found: list[str] = []
    roles = [str(r).lower() for r in (entity.get("roles") or [])]
    is_abuse = inherited_abuse or "abuse" in roles
    if is_abuse:
        found.extend(_vcard_emails(entity))
    for child in entity.get("entities") or []:
        if isinstance(child, dict):
            found.extend(_walk_rdap_entities(child, is_abuse))
    return found


def parse_rdap_abuse_contacts(payload: dict[str, Any]) -> list[str]:
    """Extract abuse-role e-mail addresses from an RDAP response."""
    if not isinstance(payload, dict):
        return []
    contacts: list[str] = []
    for entity in payload.get("entities") or []:
        if isinstance(entity, dict):
            contacts.extend(_walk_rdap_entities(entity))
    # If no explicit abuse role exists, do not guess: fall back only when the
    # response has a single top-level technical/registrant contact.
    if not contacts:
        for entity in payload.get("entities") or []:
            if isinstance(entity, dict):
                roles = {str(r).lower() for r in (entity.get("roles") or [])}
                if roles & {"technical", "registrant", "administrative"}:
                    contacts.extend(_vcard_emails(entity))
    return _dedupe(contacts)


def lookup_abuse_contacts(ip: str, timeout: int = _DEFAULT_TIMEOUT) -> list[str]:
    """Look up the abuse contact for a public IP via RDAP. Never raises."""
    ip = str(ip or "").strip()
    if not ip or not _public_ip(ip):
        return []
    if ip in _RDAP_CACHE:
        return list(_RDAP_CACHE[ip])
    try:
        response = requests.get(
            f"https://rdap.org/ip/{ip}", timeout=timeout,
            headers={"Accept": "application/rdap+json", "User-Agent": _USER_AGENT},
            allow_redirects=True,
        )
        if response.status_code != 200:
            return []
        contacts = parse_rdap_abuse_contacts(response.json())
        _RDAP_CACHE[ip] = contacts
        return list(contacts)
    except Exception:
        return []


def lookup_asn_prefixes(asn: str, timeout: int = _DEFAULT_TIMEOUT,
                        limit: int = 20) -> list[str]:
    """Return a bounded list of public prefixes announced by an ASN.

    Uses BGPView (free, no API key). Failures return an empty list; the caller
    still gets /24 or /48 suggestions derived from the resolved IPs.
    """
    number = re.sub(r"\D", "", str(asn or ""))
    if not number:
        return []
    if number in _BGP_CACHE:
        return list(_BGP_CACHE[number])
    try:
        response = requests.get(
            f"https://api.bgpview.io/asn/{number}/prefixes",
            timeout=timeout, headers={"User-Agent": _USER_AGENT},
        )
        if response.status_code != 200:
            return []
        payload = response.json()
        data = payload.get("data") or {}
        prefixes = [p.get("prefix") for p in (data.get("ipv4_prefixes") or [])]
        prefixes += [p.get("prefix") for p in (data.get("ipv6_prefixes") or [])]
        clean = [str(p) for p in prefixes if p][:max(1, int(limit))]
        _BGP_CACHE[number] = clean
        return list(clean)
    except Exception:
        return []


def parse_security_txt(text: str, base_url: str = "") -> dict[str, Any]:
    """Parse a ``security.txt`` document into contacts and metadata."""
    out: dict[str, Any] = {"url": base_url, "found": False, "contacts": [],
                           "expires": "", "canonical": "", "policy": ""}
    if not isinstance(text, str) or not text.strip():
        return out
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "contact" and value:
            out["contacts"].append(value)
        elif key == "expires" and value:
            out["expires"] = value
        elif key == "canonical" and value:
            out["canonical"] = value
        elif key == "policy" and value:
            out["policy"] = value
    out["contacts"] = _dedupe(out["contacts"])
    out["found"] = bool(out["contacts"] or out["expires"] or out["canonical"])
    return out


def fetch_security_txt(base_url: str, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Fetch and parse ``/.well-known/security.txt`` (then ``/security.txt``)."""
    base_url = str(base_url or "").strip().rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        return {"url": "", "found": False, "contacts": [], "expires": "",
                "canonical": "", "policy": ""}
    for path in ("/.well-known/security.txt", "/security.txt"):
        url = base_url + path
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True,
                                    headers={"User-Agent": _USER_AGENT})
            if response.status_code == 200 and response.text:
                parsed = parse_security_txt(response.text, url)
                if parsed["found"]:
                    return parsed
        except Exception:
            continue
    return {"url": "", "found": False, "contacts": [], "expires": "",
            "canonical": "", "policy": ""}


# ---------------------------------------------------------------------------
# guardrails
# ---------------------------------------------------------------------------
def default_guardrails(nuclei_rate_limit: int = 10) -> dict[str, Any]:
    """Unrestricted (but still bounded) defaults for unknown providers."""
    try:
        rate = max(1, min(int(nuclei_rate_limit), 150))
    except (TypeError, ValueError):
        rate = 10
    return {
        "allow_network": True,
        "allow_nuclei": True,
        "allow_directory_bruteforce": True,
        "allow_sensitive_paths": True,
        "allow_api": True,
        "allow_subdomains": True,
        "nuclei_rate_limit": rate,
        "gobuster_threads": 20,
        "gobuster_delay": "",
        "request_delay": 0.0,
        "passive_only": False,
        "overridden": False,
    }


def build_guardrails(profile: dict[str, Any],
                     requested_nuclei_rate: int = 10) -> dict[str, Any]:
    """Build concrete scan guardrails from a provider profile."""
    guard = default_guardrails(requested_nuclei_rate)
    edge = bool(profile.get("cdn_detected") or profile.get("waf_detected"))
    shared = bool(profile.get("shared_hosting"))
    paas = bool(profile.get("paas_detected"))

    if edge:
        guard.update({
            "allow_network": False,
            "allow_nuclei": False,
            "allow_directory_bruteforce": False,
            "allow_sensitive_paths": False,
            "allow_api": False,
            "passive_only": True,
            "nuclei_rate_limit": min(guard["nuclei_rate_limit"], 5),
            "gobuster_threads": 2,
            "gobuster_delay": "500ms",
            "request_delay": 0.5,
        })
    elif shared:
        guard.update({
            "nuclei_rate_limit": min(guard["nuclei_rate_limit"], 5),
            "gobuster_threads": 3,
            "gobuster_delay": "250ms",
            "request_delay": 0.25,
        })
    elif paas:
        # The provider manages the OS/kernel; network CVE scanning adds noise.
        guard.update({"allow_network": False})
    return guard


def _mode_for(profile: dict[str, Any]) -> tuple[str, str]:
    if profile.get("cdn_detected") or profile.get("waf_detected"):
        return "passive", ("Target is fronted by a CDN/WAF. Active vulnerability "
                           "scanning is disabled to avoid WAF bans and because "
                           "the edge IP is not the client's origin.")
    if profile.get("shared_hosting"):
        return "throttled", ("Shared hosting detected. Scan rates are throttled "
                             "to avoid affecting unrelated tenants on the same "
                             "host.")
    if profile.get("paas_detected"):
        return "standard", ("Managed PaaS/serverless hosting detected. OS-level "
                            "CVE scanning is disabled; application/API testing "
                            "remains enabled.")
    return "standard", "No restrictive hosting characteristics detected."


def _focus_for(profile: dict[str, Any]) -> list[str]:
    if profile.get("cdn_detected") or profile.get("waf_detected"):
        return [
            "Passive OSINT only: DNS history, certificate transparency, subdomain discovery",
            "Origin-IP discovery from certificate/history sources (no direct probing)",
            "WAF fingerprinting and rule-gap analysis only with explicit written authorization",
        ]
    if profile.get("paas_detected"):
        return [
            "Application logic and business-flow abuse",
            "API authorization (BOLA/IDOR), rate limits and token handling",
            "Exposed .git/.env/build artifacts and dependency/supply-chain risk",
        ]
    if profile.get("shared_hosting"):
        return [
            "Respect tenant isolation; low-rate, non-destructive checks only",
            "Cross-tenant path traversal and shared filesystem exposure",
            "Application-layer issues; avoid host-level resource exhaustion",
        ]
    if profile.get("cloud_detected"):
        return [
            "Public object storage (S3/GCS/Azure Blob) exposure",
            "Instance metadata service (IMDSv1) exposure from inside the workload",
            "IAM/role trust and overly permissive cloud policies",
            "Cloud WAF, security-group and public-ingress configuration",
        ]
    return ["Standard network, web and API assessment."]


def warnings_for(profile: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if profile.get("cdn_detected") or profile.get("waf_detected"):
        warnings.append(
            "CDN/WAF provider detected. Active scanning is paused; use passive "
            "recon and test the origin only with explicit authorization.")
    if profile.get("shared_hosting"):
        warnings.append(
            "Shared hosting detected. Aggressive scanning can cause a denial "
            "of service for other tenants; requests are throttled and a "
            "shared-tenant risk note is included in the report.")
    if profile.get("paas_detected"):
        warnings.append(
            "PaaS/serverless hosting detected. Kernel/service CVE scanning is "
            "not meaningful; the assessment focuses on application/API risk.")
    if profile.get("cloud_detected"):
        warnings.append(
            "Cloud infrastructure detected. Include cloud-specific controls "
            "(object storage, metadata service, IAM) in the review scope.")
    return warnings


def apply_override(profile: dict[str, Any],
                   requested_nuclei_rate: int = 10) -> dict[str, Any]:
    """Re-enable active scanning for an explicitly authorised test.

    The override is intentionally still gentle: low concurrency and a small
    request delay are kept so an authorised CDN/shared-host test does not
    become abusive.
    """
    profile = dict(profile or {})
    guard = dict(profile.get("guardrails") or default_guardrails(requested_nuclei_rate))
    for key in ("allow_network", "allow_nuclei", "allow_directory_bruteforce",
                "allow_sensitive_paths", "allow_api"):
        guard[key] = True
    guard["passive_only"] = False
    guard["overridden"] = True
    guard["nuclei_rate_limit"] = min(int(guard.get("nuclei_rate_limit") or 5), 5)
    guard["gobuster_threads"] = min(int(guard.get("gobuster_threads") or 20), 5)
    guard["gobuster_delay"] = guard.get("gobuster_delay") or "250ms"
    guard["request_delay"] = max(float(guard.get("request_delay") or 0.0), 0.2)
    profile["guardrails"] = guard
    profile["guardrail_override"] = True
    profile["warnings"] = list(profile.get("warnings") or []) + [
        "Guardrails overridden by the operator — active scanning is permitted. "
        "Confirm written authorization for the CDN/WAF or shared host before "
        "continuing."
    ]
    return profile


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------
class InfrastructureMapper:
    """Classify hosting and produce scan guardrails for a target."""

    def __init__(self, target: str, evidence=None,
                 timeout: int = _DEFAULT_TIMEOUT, fetch_intel: bool = True,
                 fetch_security_txt_file: bool = True):
        self.target = target
        self.evidence = evidence
        self.timeout = timeout
        self.fetch_intel = fetch_intel
        self.fetch_security_txt_file = fetch_security_txt_file

    def analyze(self, geo: dict[str, Any] | None = None,
                requested_nuclei_rate: int = 10) -> dict[str, Any]:
        """Return the structured infrastructure profile.

        ``geo`` may be an existing :class:`GeoLocator` result (avoids a second
        lookup). When omitted, a lookup is performed.
        """
        geo = geo if isinstance(geo, dict) else GeoLocator(
            self.target, evidence=self.evidence, timeout=self.timeout).locate()
        profile = classify_hosting(geo)
        profile["geo_summary"] = geo.get("summary", "")
        profile["web_server"] = geo.get("web_server") or {}
        profile["private"] = bool(profile.get("private") or _is_private(
            (profile.get("resolved_ips") or [""])[0]))

        abuse = list(profile.get("abuse_contacts") or [])
        security: dict[str, Any] = {"url": "", "found": False, "contacts": [],
                                    "expires": "", "canonical": "", "policy": ""}
        prefixes: list[str] = []

        if self.fetch_intel and not profile.get("private"):
            primary_ip = (profile.get("resolved_ips") or [""])[0]
            abuse.extend(lookup_abuse_contacts(primary_ip, timeout=self.timeout))
            if profile.get("asn"):
                prefixes = lookup_asn_prefixes(profile["asn"],
                                               timeout=self.timeout)
            if self.fetch_security_txt_file:
                base = (profile.get("web_server") or {}).get("url") or ""
                if not base and profile.get("hostname"):
                    base = f"https://{profile['hostname']}"
                security = fetch_security_txt(base, timeout=self.timeout)
                abuse.extend(security.get("contacts") or [])

        pivots = _dedupe([
            *(_candidate_prefix(ip) for ip in profile.get("resolved_ips") or []),
            *prefixes,
        ])
        profile["abuse_contacts"] = _dedupe(abuse)
        profile["security_txt"] = security
        profile["pivot_targets"] = [p for p in pivots if p][:20]
        profile["pivot_note"] = (
            "Suggestions only. Verify ownership and written authorization "
            "before scanning any pivot prefix; SmartVAPT never scans them "
            "automatically.")
        profile["pivot_lookup_urls"] = self._pivot_urls(profile)
        profile["recommended_mode"], profile["mode_reason"] = _mode_for(profile)
        profile["guardrails"] = build_guardrails(profile, requested_nuclei_rate)
        profile["warnings"] = warnings_for(profile)
        profile["legal_notice"] = self._legal_notice(profile)
        profile["dynamic_focus"] = _focus_for(profile)
        profile["intel_sources"] = self._sources(profile)
        provider_label = profile.get("provider_type_label") or ""
        profile["provider_label"] = (
            profile.get("provider") if not provider_label or
            provider_label == profile.get("provider")
            else f"{profile.get('provider')} ({provider_label})")

        if self.evidence:
            try:
                self.evidence.save_json("infrastructure", profile)
            except Exception:
                pass
        return profile

    @staticmethod
    def _legal_notice(profile: dict[str, Any]) -> str:
        if profile.get("cdn_detected") or profile.get("waf_detected"):
            return (
                "CDN/WAF notice: this target is fronted by a third-party edge "
                "provider. The provider's acceptable-use policy may prohibit "
                "vulnerability scanning of its edge. Test the origin only with "
                "written authorization from the asset owner and, where "
                "required, the provider.")
        if profile.get("shared_hosting"):
            return (
                "Shared-tenant risk notice: the target shares infrastructure "
                "with unrelated customers. Aggressive or high-volume testing "
                "can degrade or deny service to those tenants. SmartVAPT "
                "throttles requests, but the tester remains responsible for "
                "authorization and for complying with the hosting provider's "
                "acceptable-use policy.")
        if profile.get("paas_detected"):
            return (
                "PaaS notice: the platform provider manages the operating "
                "system and runtime. Test application and API behaviour only; "
                "do not attempt host-level exploitation or resource-exhaustion "
                "attacks against shared platform infrastructure.")
        return ""

    @staticmethod
    def _pivot_urls(profile: dict[str, Any]) -> list[str]:
        urls: list[str] = []
        asn = profile.get("asn") or ""
        if asn:
            number = re.sub(r"\D", "", asn)
            urls.extend([
                f"https://bgp.he.net/{asn}",
                f"https://stat.ripe.net/AS{number}",
                f"https://www.shodan.io/search?query=asn%3A{asn}",
            ])
        primary_ip = (profile.get("resolved_ips") or [""])[0]
        if primary_ip:
            urls.append(f"https://rdap.org/ip/{primary_ip}")
        return urls

    @staticmethod
    def _sources(profile: dict[str, Any]) -> list[str]:
        sources = ["GeoLocator (ip-api.com / ipwho.is)"]
        if profile.get("private"):
            return sources
        sources.append("RDAP abuse contacts")
        if profile.get("asn"):
            sources.append("BGPView ASN prefixes")
        if (profile.get("security_txt") or {}).get("found"):
            sources.append("security.txt")
        return sources


if __name__ == "__main__":  # quick CLI: python infrastructure_mapper.py <target>
    import json
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(json.dumps(InfrastructureMapper(tgt).analyze(), indent=2, default=str))
