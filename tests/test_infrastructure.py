"""Tests for provider classification and scan guardrails."""
from infrastructure_mapper import (InfrastructureMapper, apply_override,
                                   build_guardrails, default_guardrails,
                                   parse_rdap_abuse_contacts,
                                   parse_security_txt)


def _geo(org="", isp="", asn="", server="", host="example.com",
         resolved=None, private=False):
    primary = {
        "found": True, "organization": org, "isp": isp or org, "asn": asn,
        "country": "US", "country_code": "US", "city": "Test",
    }
    if private:
        primary = {"private": True, "found": False}
    return {
        "target": f"https://{host}",
        "hostname": host,
        "resolved_ips": [] if resolved is None else resolved,
        "locations": [primary] if primary else [],
        "primary": primary,
        "web_server": {"url": f"https://{host}", "port": 443,
                       "server": server, "status": 200},
        "summary": "Test location",
    }


def _profile(geo, **kwargs):
    # fetch_intel=False keeps tests offline/deterministic.
    return InfrastructureMapper("https://example.com", fetch_intel=False,
                                fetch_security_txt_file=False,
                                **kwargs).analyze(geo)


def test_cloudflare_triggers_passive_mode_and_disables_active_checks():
    profile = _profile(_geo(org="Cloudflare, Inc.", asn="AS13335 CLOUDFLARENET",
                            server="cloudflare", host="example.com"))
    assert profile["cdn_detected"] is True
    assert profile["waf_detected"] is True
    assert profile["provider"] == "Cloudflare"
    assert profile["recommended_mode"] == "passive"
    guard = profile["guardrails"]
    assert guard["allow_network"] is False
    assert guard["allow_nuclei"] is False
    assert guard["allow_directory_bruteforce"] is False
    assert guard["allow_sensitive_paths"] is False
    assert guard["allow_api"] is False
    assert guard["passive_only"] is True
    assert guard["nuclei_rate_limit"] <= 5
    assert profile["warnings"]


def test_shared_hosting_throttles_but_keeps_active_checks():
    profile = _profile(_geo(org="GoDaddy.com, LLC", asn="AS26496 GO-DADDY-COM-LLC",
                            server="Apache", host="example.com"))
    assert profile["shared_hosting"] is True
    assert profile["recommended_mode"] == "throttled"
    guard = profile["guardrails"]
    assert guard["allow_network"] is True
    assert guard["allow_nuclei"] is True
    assert guard["nuclei_rate_limit"] <= 5
    assert guard["gobuster_threads"] <= 3
    assert guard["gobuster_delay"]
    assert guard["request_delay"] > 0


def test_paas_disables_os_level_scanning_but_keeps_app_checks():
    profile = _profile(_geo(org="Vercel, Inc.", asn="AS16509 AMAZON-02",
                            server="Vercel", host="example.vercel.app"))
    assert profile["paas_detected"] is True
    assert profile["recommended_mode"] == "standard"
    guard = profile["guardrails"]
    assert guard["allow_network"] is False
    assert guard["allow_nuclei"] is True
    assert guard["allow_api"] is True
    assert any("Application logic" in item for item in profile["dynamic_focus"])


def test_cloud_provider_keeps_standard_mode_and_cloud_focus():
    profile = _profile(_geo(org="Amazon.com, Inc.", asn="AS16509 AMAZON-02",
                            server="AmazonS3", host="example.com"))
    assert profile["cloud_detected"] is True
    assert profile["recommended_mode"] == "standard"
    assert profile["guardrails"]["allow_network"] is True
    assert any("object storage" in item for item in profile["dynamic_focus"])


def test_linode_cloud_is_not_misclassified_as_akamai_cdn_edge():
    profile = _profile(_geo(org="Akamai Technologies, Inc.", isp="Linode",
                            asn="AS63949", server="Apache/2.4.7 (Ubuntu)",
                            host="scanme.nmap.org"))
    assert profile["provider"] == "Linode / Akamai Cloud"
    assert profile["cdn_detected"] is False
    assert profile["recommended_mode"] == "standard"


def test_legal_notice_reflects_provider_risk():
    cdn = _profile(_geo(org="Cloudflare, Inc.", asn="AS13335 CLOUDFLARENET",
                        server="cloudflare"))
    shared = _profile(_geo(org="GoDaddy.com, LLC", asn="AS26496",
                           server="Apache"))
    paas = _profile(_geo(org="Vercel, Inc.", asn="AS16509",
                         server="Vercel", host="example.vercel.app"))
    plain = _profile(_geo(org="Example ISP", asn="AS64500", server="nginx"))
    assert "CDN/WAF notice" in cdn["legal_notice"]
    assert "Shared-tenant risk notice" in shared["legal_notice"]
    assert "PaaS notice" in paas["legal_notice"]
    assert plain["legal_notice"] == ""


def test_unknown_provider_uses_standard_defaults():
    profile = _profile(_geo(org="Example ISP", asn="AS64500 EXAMPLE-ISP",
                            server="nginx", host="example.com"))
    assert profile["provider_type"] in ("isp", "unknown")
    assert profile["recommended_mode"] == "standard"
    assert profile["guardrails"] == default_guardrails(10)


def test_override_reenables_active_checks_but_stays_gentle():
    profile = _profile(_geo(org="Cloudflare, Inc.", asn="AS13335 CLOUDFLARENET",
                            server="cloudflare"))
    overridden = apply_override(profile, requested_nuclei_rate=10)
    guard = overridden["guardrails"]
    assert overridden["guardrail_override"] is True
    assert guard["overridden"] is True
    assert guard["allow_network"] is True
    assert guard["allow_nuclei"] is True
    assert guard["allow_directory_bruteforce"] is True
    assert guard["nuclei_rate_limit"] <= 5
    assert guard["gobuster_threads"] <= 5
    assert guard["request_delay"] >= 0.2


def test_classification_handles_private_addresses_without_external_intel():
    profile = _profile(_geo(private=True, host="localhost"))
    assert profile["private"] is True
    assert profile["provider_type"] == "private"
    assert profile["recommended_mode"] == "standard"


def test_rdap_parser_extracts_abuse_role_contacts():
    payload = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example"]],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [
                            ["fn", {}, "text", "Abuse Desk"],
                            ["email", {}, "text", "abuse@example.net"],
                        ]],
                    }
                ],
            }
        ]
    }
    contacts = parse_rdap_abuse_contacts(payload)
    assert contacts == ["abuse@example.net"]


def test_security_txt_parser():
    text = """
# security policy
Contact: mailto:security@example.com
Contact: https://example.com/report
Expires: 2027-01-01T00:00:00Z
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/policy
"""
    parsed = parse_security_txt(text)
    assert parsed["found"] is True
    assert "mailto:security@example.com" in parsed["contacts"]
    assert parsed["expires"] == "2027-01-01T00:00:00Z"


def test_guardrail_builder_prioritises_cdn_over_shared_hosting():
    profile = {"cdn_detected": True, "waf_detected": True,
               "shared_hosting": True, "paas_detected": False}
    guard = build_guardrails(profile, requested_nuclei_rate=20)
    assert guard["passive_only"] is True
    assert guard["allow_network"] is False
    assert guard["nuclei_rate_limit"] <= 5
