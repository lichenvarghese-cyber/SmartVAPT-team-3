"""Privacy-preserving AI report generation using a local small language model.

By default SmartVAPT talks to a locally-running SLM (Ollama / an
OpenAI-compatible endpoint) so that scan findings never leave the machine.
No API key is required and no data is sent to a third-party service.

Supported providers:
  - "ollama":   Ollama (http://localhost:11434)  -- default
  - "openai":   any OpenAI-compatible chat endpoint (LM Studio, vLLM, ...)
"""
import json
import os
from typing import Any

import requests

from config import SLM_BASE_URL, SLM_MODEL, SLM_PROVIDER, SLM_TIMEOUT

SYSTEM_PROMPT = """You are a Senior Penetration Tester and CISO advisor.
You will receive raw vulnerability data from an automated VAPT scan covering:
1. Network infrastructure (open ports, services, CVEs)
2. Web application security (HTTP headers, exposed directories)
3. Domain/identity security (SPF, DMARC)

Your job:
- Correlate findings into business risk.
- Map issues to OWASP Top 10 where applicable.
- Map issues to MITRE ATT&CK techniques where applicable.
- Prioritize by CVSS and exploitability.
- Produce a concise EXECUTIVE SUMMARY (non-technical) and a TECHNICAL REMEDIATION section with exact commands/config snippets.
- Use professional language suitable for C-suite.

Return ONLY valid JSON in this schema:
{
  "executive_summary": "...",
  "overall_risk": "Critical|High|Medium|Low",
  "risk_score": 0-10,
  "top_findings": [
    {"finding_id": "exact id from the findings list", "title": "...", "severity": "...", "business_impact": "...", "remediation": "...", "mitre_attack": ["T####"]}
  ],
  "technical_remediation": [
    {"finding_id": "exact id from the findings list", "finding": "...", "owasp": "...", "mitre_attack": "T####", "steps": ["...", "..."], "commands": ["..."]}
  ],
  "conclusion": "..."
}
Every finding_id MUST be copied verbatim from the supplied findings list.
Do not invent findings, CVEs, ports, or targets that are not in the findings list.
"""


class AIEngine:
    def __init__(self, provider: str | None = None, model: str | None = None,
                 base_url: str | None = None, timeout: int | None = None,
                 api_key: str | None = None):
        # ``api_key`` is accepted for backward compatibility but ignored: the
        # local SLM does not use remote credentials.
        self.provider = (provider or SLM_PROVIDER or "ollama").lower()
        self.model = model or SLM_MODEL
        self.base_url = (base_url or SLM_BASE_URL).rstrip("/")
        self.timeout = timeout or SLM_TIMEOUT

    # ------------------------------------------------------------------ call
    def _call_ollama(self, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2},
        }
        r = requests.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return (data.get("response") or "").strip()

    def _call_openai(self, prompt: str) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        r = requests.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return (data["choices"][0]["message"]["content"] or "").strip()

    def _call(self, prompt: str) -> str:
        if self.provider == "openai":
            return self._call_openai(prompt)
        return self._call_ollama(prompt)

    # ---------------------------------------------------------------- analyze
    def analyze(self, findings: list, scan_summary: dict) -> dict:
        prompt = self._build_prompt(findings, scan_summary)
        try:
            text = self._call(prompt)
            if text.startswith("```"):
                text = text.split("```", 2)[1]
                text = text.removeprefix("json").strip()
            return json.loads(text)
        except json.JSONDecodeError:
            # The model answered but not with clean JSON; keep its text.
            return {
                "executive_summary": text if "text" in locals() else "",
                "overall_risk": "Unknown",
                "risk_score": 0,
                "top_findings": [],
                "technical_remediation": [],
                "conclusion": "Local SLM returned a non-JSON response.",
            }
        except Exception as e:
            fallback = self._fallback_summary(findings)
            fallback["conclusion"] = (
                f"Note: local SLM analysis unavailable ({type(e).__name__}: {e}). "
                "This report was generated using deterministic severity mapping. "
                "Ensure the SLM is running (e.g. 'ollama serve' with model "
                f"'{self.model}') and re-run for the full AI narrative."
            )
            return fallback

    def _build_prompt(self, findings: list, scan_summary: dict) -> str:
        # Keep the prompt compact so it fits small-model context windows.
        trimmed = findings[:25]
        return (
            "Analyze the following VAPT scan results and produce a JSON report "
            "as specified in your system instructions.\n\n"
            f"=== UNIFIED FINDINGS ({len(findings)} total, showing {len(trimmed)}) ===\n"
            f"{json.dumps(trimmed, indent=2, default=str)[:8000]}\n\n"
            f"=== SCAN SUMMARY ===\n"
            f"{json.dumps(scan_summary, indent=2, default=str)[:1500]}\n\n"
            "Return ONLY JSON. No markdown. No explanations outside JSON."
        )

    # ---------------------------------------------------------------- fallback
    @staticmethod
    def _fallback_summary(findings: list) -> dict:
        """Generate a real executive summary from findings without the AI."""
        confirmed = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        unconfirmed = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev not in confirmed:
                continue
            conf = str(f.get("confidence") or "").lower()
            if ("unconfirmed" in conf or "patched" in conf or "banner" in conf
                    or (f.get("cve") and not f.get("confirmed"))):
                unconfirmed[sev] += 1
            else:
                confirmed[sev] += 1

        total = len(findings)
        n_conf = sum(confirmed.values())
        n_unconf = sum(unconfirmed.values())

        if confirmed["critical"]:
            risk, score = "Critical", min(10, 8 + confirmed["critical"] * 0.5)
        elif confirmed["high"]:
            risk, score = "High", min(10, 6 + confirmed["high"] * 0.4)
        elif confirmed["medium"]:
            risk, score = "Medium", 4.0
        elif confirmed["low"] or confirmed["info"]:
            risk, score = "Low", 2.0
        elif n_unconf:
            risk, score = "Medium", 3.0
        else:
            risk, score = "Low", 1.0

        summary = (
            f"SmartVAPT identified {total} findings across the assessed attack surface. "
            f"{n_conf} were confirmed by an active check "
            f"({confirmed['critical']} critical, {confirmed['high']} high, "
            f"{confirmed['medium']} medium, {confirmed['low']} low, {confirmed['info']} info); "
            f"the remaining {n_unconf} are banner-matched CVE hypotheses "
            f"(distro backports may already cover many). Overall risk has been rated "
            f"{risk.upper()} ({score:.1f}/10) based on confirmed findings only."
        )

        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        def rank(f):
            conf = str(f.get("confidence") or "").lower()
            confirmed_flag = 0 if ("unconfirmed" in conf or "patched" in conf) else 1
            return (confirmed_flag, order.get(str(f.get("severity", "")).lower(), 0),
                    float(f.get("cvss") or 0))
        top = sorted(findings, key=rank, reverse=True)[:10]

        return {
            "executive_summary": summary,
            "overall_risk": risk,
            "risk_score": round(score, 1),
            "top_findings": [
                {"title": f.get("title", ""),
                 "severity": (f.get("severity") or "").capitalize(),
                 "business_impact": f.get("description", ""),
                 "remediation": f.get("remediation", "")} for f in top
            ],
            "technical_remediation": [
                {"finding": f.get("title", ""),
                 "owasp": f.get("owasp", "N/A"),
                 "steps": [f.get("remediation", "See finding description.")],
                 "commands": []} for f in top if f.get("severity") in ("critical", "high")
            ],
            "conclusion": "",
        }