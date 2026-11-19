"""Deterministic exploit-likelihood enrichment: FIRST EPSS + CISA KEV.

Both feeds are public and read-only. Responses are cached locally for 24
hours so repeated scans do not hammer the services. Any network failure
degrades gracefully: findings keep their CVSS severity and the report says
the enrichment source was unavailable. No AI is involved.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
DEFAULT_CACHE = os.getenv("SMARTVAPT_THREAT_INTEL_CACHE",
                          "threat_intel_cache.json")
CACHE_TTL = 24 * 3600
DEFAULT_TIMEOUT = 8
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _cache_key(cache_path: str) -> str:
    return os.path.abspath(cache_path)


def _load_cache(cache_path: str) -> dict:
    try:
        with open(cache_path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache_path: str, data: dict) -> None:
    try:
        tmp = f"{cache_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, cache_path)
    except OSError:
        pass


def _fresh(entry: dict, ttl: int = CACHE_TTL) -> bool:
    try:
        return (time.time() - float(entry.get("fetched_at", 0))) < ttl
    except (TypeError, ValueError):
        return False


def _get_json(url: str, params: dict | None = None,
              timeout: int = DEFAULT_TIMEOUT) -> dict:
    response = requests.get(
        url, params=params, timeout=timeout,
        headers={"User-Agent": "SmartVAPT threat-intel enrichment"})
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("unexpected threat-intel response")
    return data


def fetch_kev(cache_path: str = DEFAULT_CACHE,
              timeout: int = DEFAULT_TIMEOUT) -> tuple[dict, str | None]:
    """Return ``{cve: entry}`` from the CISA KEV catalog."""
    cache = _load_cache(cache_path)
    entry = cache.get("kev") or {}
    if _fresh(entry):
        return entry.get("data") or {}, entry.get("error")

    try:
        payload = _get_json(KEV_URL, timeout=timeout)
        catalog = {}
        for item in payload.get("vulnerabilities") or []:
            cve = str(item.get("cveID") or "").upper()
            if not cve:
                continue
            catalog[cve] = {
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "ransomware": str(item.get("knownRansomwareCampaignUse")
                                  or "Unknown"),
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "name": item.get("vulnerabilityName"),
            }
        cache["kev"] = {"fetched_at": time.time(), "data": catalog,
                        "error": None}
        _save_cache(cache_path, cache)
        return catalog, None
    except Exception as exc:  # offline / upstream error: keep old cache
        error = f"KEV unavailable: {exc}"
        cache["kev"] = {"fetched_at": entry.get("fetched_at", 0),
                        "data": entry.get("data") or {}, "error": error}
        _save_cache(cache_path, cache)
        return entry.get("data") or {}, error


def fetch_epss(cves: list[str], cache_path: str = DEFAULT_CACHE,
               timeout: int = DEFAULT_TIMEOUT) -> tuple[dict, str | None]:
    """Return ``{cve: {epss, percentile}}`` from the FIRST EPSS API."""
    wanted = sorted({c.upper() for c in cves if _CVE_RE.fullmatch(c or "")})
    if not wanted:
        return {}, None
    cache = _load_cache(cache_path)
    entry = cache.get("epss") or {}
    cached = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    missing = [c for c in wanted if c not in cached]
    age_ok = _fresh(entry, ttl=CACHE_TTL)
    if not missing and age_ok:
        return {c: cached[c] for c in wanted}, entry.get("error")

    scores = dict(cached)
    error = None
    try:
        for i in range(0, len(missing or []), 100):
            chunk = (missing or [])[i:i + 100]
            payload = _get_json(EPSS_URL, params={
                "cve": ",".join(chunk), "limit": len(chunk)}, timeout=timeout)
            for row in payload.get("data") or []:
                cve = str(row.get("cve") or "").upper()
                if not cve:
                    continue
                try:
                    scores[cve] = {
                        "epss": round(float(row.get("epss")), 4),
                        "percentile": round(float(row.get("percentile")), 4),
                    }
                except (TypeError, ValueError):
                    continue
        # Remember that a CVE has no score so we do not ask again every scan.
        for cve in missing or []:
            scores.setdefault(cve, {})
    except Exception as exc:
        error = f"EPSS unavailable: {exc}"

    cache["epss"] = {"fetched_at": time.time() if not error
                     else entry.get("fetched_at", 0),
                     "data": scores, "error": error}
    _save_cache(cache_path, cache)
    return {c: scores.get(c, {}) for c in wanted}, error


def _first_cve(finding: dict) -> str | None:
    found = _CVE_RE.findall(str(finding.get("cve") or ""))
    return found[0].upper() if found else None


def enrich_findings(findings: list[dict], cache_path: str = DEFAULT_CACHE,
                    timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Attach EPSS/KEV fields to findings that reference a CVE.

    Adds ``epss``, ``epss_percentile``, ``kev``, ``kev_date_added``,
    ``kev_due_date``, ``kev_ransomware`` and ``exploit_priority``.
    """
    cves = sorted({c for f in findings if (c := _first_cve(f))})
    summary = {
        "source": "FIRST EPSS + CISA KEV",
        "cves_checked": len(cves),
        "epss_scored": 0,
        "kev_matches": 0,
        "errors": [],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if not cves:
        summary["source"] = "none"
        return summary

    kev, kev_error = fetch_kev(cache_path=cache_path, timeout=timeout)
    epss, epss_error = fetch_epss(cves, cache_path=cache_path, timeout=timeout)
    summary["errors"] = [e for e in (kev_error, epss_error) if e]

    for finding in findings:
        cve = _first_cve(finding)
        if not cve:
            continue
        score = epss.get(cve) or {}
        kev_info = kev.get(cve) or {}
        finding["epss"] = score.get("epss")
        finding["epss_percentile"] = score.get("percentile")
        finding["kev"] = bool(kev_info)
        if kev_info:
            summary["kev_matches"] += 1
            finding["kev_date_added"] = kev_info.get("date_added")
            finding["kev_due_date"] = kev_info.get("due_date")
            finding["kev_ransomware"] = kev_info.get("ransomware")
        if score:
            summary["epss_scored"] += 1
        if finding["kev"]:
            finding["exploit_priority"] = "known_exploited"
        elif score.get("epss") is not None and score["epss"] >= 0.5:
            finding["exploit_priority"] = "high_likelihood"
        elif score.get("epss") is not None and score["epss"] >= 0.1:
            finding["exploit_priority"] = "elevated"
        elif score.get("epss") is not None:
            finding["exploit_priority"] = "low"
        else:
            finding["exploit_priority"] = "unknown"
    return summary
