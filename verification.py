"""Grounding / provenance verification for AI-generated report content.

SmartVAPT's AI engine is a local SLM. Its *structured* output (top findings
and remediation items) must be traceable to findings produced by this VAPT
tool. This module verifies each AI claim against the canonical finding list
and attaches a tamper-evident provenance record (scan id + SHA-256 of the
findings) to the report.

The executive summary is free-form narrative and cannot be proven verbatim;
it is checked for obvious numeric contradictions against the finding counts
and labelled accordingly.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def findings_digest(findings: list[dict[str, Any]]) -> str:
    """SHA-256 over a canonical JSON representation of the findings.

    Two scans with identical findings therefore produce the same digest,
    which lets a report be tied back to an exact scan result set.
    """
    canonical_findings = sorted(findings, key=lambda f: str(f.get("id", "")))
    canonical = json.dumps(canonical_findings, sort_keys=True, default=str,
                          separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _finding_index(findings: list[dict[str, Any]]):
    by_id = {str(f.get("id", "")): f for f in findings if f.get("id") is not None}
    by_title: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_title.setdefault(_norm(f.get("title", "")), []).append(f)
    return by_id, by_title


def _match_finding(item: dict[str, Any], findings: list[dict[str, Any]],
                    by_id: dict[str, dict[str, Any]],
                    by_title: dict[str, list[dict[str, Any]]]):
    """Return (matched_finding, match_method) or (None, None).

    Priority: exact finding_id -> exact normalized title -> fuzzy title.
    """
    finding_id = str(item.get("finding_id") or item.get("id") or "").strip()
    if finding_id and finding_id in by_id:
        return by_id[finding_id], "finding_id"

    title = _norm(item.get("title") or item.get("finding") or "")
    if title and title in by_title:
        return by_title[title][0], "title"

    best = None
    for f in findings:
        ratio = difflib.SequenceMatcher(None, title, _norm(f.get("title", ""))).ratio()
        if ratio >= 0.85 and (best is None or ratio > best[1]):
            best = (f, ratio)
    if best:
        return best[0], "fuzzy_title"
    return None, None


def _verify_item(item: dict[str, Any], findings, by_id, by_title) -> dict[str, Any]:
    matched, method = _match_finding(item, findings, by_id, by_title)
    if matched is None:
        return {
            "input": item,
            "grounded": False,
            "status": "unmatched",
            "reason": "No finding in this SmartVAPT scan matches this AI claim; dropped.",
        }

    severity = str(item.get("severity") or "").lower()
    matched_severity = str(matched.get("severity") or "").lower()
    severity_corrected = bool(severity and severity != matched_severity)
    return {
        "input": item,
        "grounded": True,
        "status": "matched",
        "match_method": method,
        "finding_id": str(matched.get("id", "")),
        "title": str(matched.get("title", item.get("title", ""))),
        "severity_corrected": severity_corrected,
        "reason": (f"Matched finding {matched.get('id')} ({method})"
                   + ("; severity corrected to scan value" if severity_corrected else "")),
    }


def _verify_summary_numbers(summary: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check obvious '<number> <severity>' claims in the narrative against the
    real severity counts. Returns a list of contradictions (empty = clean)."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1

    contradictions = []
    text = str(summary or "")
    # e.g. "5 critical", "12 critical findings", "34 high"
    pattern = re.compile(r"(\d+)\s+(critical|high|medium|low|info)\b", re.IGNORECASE)
    for m in pattern.finditer(text):
        claimed = int(m.group(1))
        severity = m.group(2).lower()
        if claimed != counts[severity]:
            contradictions.append({
                "claim": m.group(0),
                "claimed": claimed,
                "actual": counts[severity],
                "severity": severity,
            })
    return contradictions


def verify_ai_result(findings: list[dict[str, Any]], ai_result: dict[str, Any],
                     scan_id: str | None = None) -> dict[str, Any]:
    """Verify every structured AI claim against the canonical findings.

    Returns a verification record. The report generator and JSON/HTML
    exporters embed this record so the output can be audited.
    """
    by_id, by_title = _finding_index(findings)
    top_checks = [_verify_item(item, findings, by_id, by_title)
                  for item in (ai_result.get("top_findings") or [])]
    rem_checks = [_verify_item(item, findings, by_id, by_title)
                  for item in (ai_result.get("technical_remediation") or [])]

    grounded_top = [c for c in top_checks if c["grounded"]]
    grounded_rem = [c for c in rem_checks if c["grounded"]]
    unmatched = [c for c in (top_checks + rem_checks) if not c["grounded"]]

    contradictions = _verify_summary_numbers(
        ai_result.get("executive_summary", ""), findings)

    verified = not unmatched and not contradictions
    total = len(top_checks) + len(rem_checks)
    grounded = len(grounded_top) + len(grounded_rem)

    return {
        "verified": verified,
        "status": "verified" if verified else "not_verified",
        "scan_id": scan_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "data_sha256": findings_digest(findings),
        "tool": "SmartVAPT",
        "structured_claims": total,
        "grounded_claims": grounded,
        "unmatched_claims": len(unmatched),
        "summary_contradictions": contradictions,
        "top_findings": top_checks,
        "technical_remediation": rem_checks,
        "note": (
            "All structured AI claims were matched against this scan's findings. "
            "The executive summary is free-form narrative; numeric severity claims "
            "were checked against the finding counts."
        ),
    }


def apply_verification(findings: list[dict[str, Any]], ai_result: dict[str, Any],
                       scan_id: str | None = None) -> dict[str, Any]:
    """Return a copy of *ai_result* with ungrounded AI claims removed and
    severity mismatches corrected to the values actually produced by the scan.

    The verification record is attached under ``ai_result['verification']``.
    """
    result = dict(ai_result)
    verification = verify_ai_result(findings, ai_result, scan_id=scan_id)

    def _clean(items):
        out = []
        for check in items:
            if not check["grounded"]:
                continue
            item = dict(check["input"])
            matched_id = check.get("finding_id")
            matched = next((f for f in findings if str(f.get("id")) == matched_id), None)
            if matched is not None:
                if "severity" in item and item.get("severity"):
                    item["severity"] = matched.get("severity", item.get("severity"))
                item["finding_id"] = matched_id
                item["title"] = matched.get("title", item.get("title", ""))
            out.append(item)
        return out

    result["top_findings"] = _clean(verification["top_findings"])
    result["technical_remediation"] = _clean(verification["technical_remediation"])
    result["verification"] = verification
    return result
