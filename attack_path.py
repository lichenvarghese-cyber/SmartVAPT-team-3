"""Deterministic attack-path graph built from scan results.

No network access and no AI: the graph is a stable projection of the
findings, exposed services, web asset and DNS posture. It is rendered in the
dashboard with Graphviz and stored as JSON/DOT for exports.
"""
from __future__ import annotations

import re
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_FILL = {
    "critical": "#fecaca", "high": "#fed7aa", "medium": "#fef08a",
    "low": "#bbf7d0", "info": "#e2e8f0",
}
KIND_FILL = {
    "target": "#dbeafe", "dns": "#ede9fe", "web": "#dcfce7",
    "service": "#f1f5f9", "impact": "#fee2e2", "finding": "#e2e8f0",
}


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", str(text or "")).strip("-")
    return slug or "node"


def _dot_escape(text: Any) -> str:
    return (str(text).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\r", "").replace("\n", "\\n"))


def _severity(finding: dict) -> str:
    sev = str(finding.get("severity", "info")).lower()
    return sev if sev in SEVERITY_ORDER else "info"


def _impact_for(finding: dict) -> tuple[str, str]:
    """Map a finding to a business-impact node (deterministic keywords)."""
    text = " ".join(str(finding.get(k) or "") for k in
                    ("title", "description", "owasp", "cve")).lower()

    def hit(*words):
        return any(w in text for w in words)

    if hit("spf", "dmarc", "email spoof", "spoofing"):
        return "impact-email", "Email spoofing / phishing"
    if hit("takeover", "dangling cname"):
        return "impact-takeover", "Subdomain takeover"
    if hit("sql injection", "command injection", "remote code", "rce",
           "deserialization", "code execution"):
        return "impact-rce", "Code execution"
    if hit("credential", "password", ".env", "private key", "api key",
           "sensitive file", "secret"):
        return "impact-credential", "Credential exposure"
    if hit("csrf", "cross-site request"):
        return "impact-csrf", "Action forgery"
    if hit("cors", "cross-origin"):
        return "impact-cors", "Cross-origin data theft"
    if hit("cookie", "session"):
        return "impact-session", "Session hijacking"
    if hit("xss", "content-security-policy", "csp", "clickjacking",
           "x-frame", "header"):
        return "impact-client", "Client-side compromise"
    if hit("tls", "ssl", "certificate", "cipher", "hsts"):
        return "impact-tls", "Traffic interception"
    if hit("cve-", "outdated", "vulnerable version", "regression"):
        return "impact-service", "Service compromise"
    if hit("api", "graphql", "swagger", "openapi", "jwt", "bola", "idor"):
        return "impact-api", "API abuse"
    if hit("redirect"):
        return "impact-redirect", "Open redirect / phishing"
    if hit("subdomain", "recon", "disclos"):
        return "impact-recon", "Reconnaissance"
    return "impact-misc", "Security misconfiguration"


def _http_service(port: dict) -> bool:
    service = str(port.get("service") or "").lower()
    return any(x in service for x in ("http", "https", "ssl"))


def build_attack_path(results: dict, max_findings: int = 30) -> dict:
    """Build nodes/edges/DOT/chokepoints from a completed scan result."""
    target = str(results.get("target") or "target")
    findings = [f for f in (results.get("findings") or [])
                if isinstance(f, dict)]
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str, str]] = []

    def add_node(node_id: str, label: str, kind: str,
                 severity: str | None = None) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label, "kind": kind,
                              "severity": severity}

    def add_edge(source: str, dest: str, label: str) -> None:
        edge = (source, dest, label)
        if edge not in edges:
            edges.append(edge)

    add_node("target", target, "target")

    dns = results.get("dns") or {}
    if isinstance(dns, dict) and dns and not dns.get("error"):
        add_node("dns", f"DNS: {dns.get('domain') or target}", "dns")
        add_edge("target", "dns", "owns")

    web = results.get("web") or {}
    web_url = (results.get("web_audited_url")
               or (web.get("headers") or {}).get("url")
               or (results.get("geo") or {}).get("web_server", {}).get("url")
               or target)
    if isinstance(web, dict) and web and not web.get("error"):
        add_node("web", f"Web: {web_url}", "web")
        add_edge("target", "web", "serves")

    services: dict[int, str] = {}
    network = results.get("network") or {}
    for host in network.get("hosts") or []:
        for port in host.get("ports") or []:
            try:
                number = int(port.get("port"))
            except (TypeError, ValueError):
                continue
            proto = str(port.get("protocol") or "tcp")
            service = str(port.get("service") or "").strip()
            node_id = f"svc-{number}-{proto}"
            label = f"{number}/{proto}"
            if service:
                label += f" {service}"
            add_node(node_id, label, "service")
            add_edge("target", node_id, "exposes")
            services[number] = node_id
            if _http_service(port) and "web" in nodes:
                add_edge(node_id, "web", "hosts")

    ranked = sorted(findings, key=lambda f: (
        -SEVERITY_ORDER.get(_severity(f), 0), str(f.get("id") or "")))
    mapped = ranked[:max_findings]
    for finding in mapped:
        finding_id = str(finding.get("id") or "finding")
        severity = _severity(finding)
        title = str(finding.get("title") or "")[:70]
        node_id = f"f-{_slug(finding_id)}"
        add_node(node_id, f"{finding_id}: {title}", "finding", severity)

        parent = "target"
        try:
            port = int(finding.get("port"))
        except (TypeError, ValueError):
            port = None
        if port is not None:
            if port not in services:
                services[port] = f"svc-{port}-tcp"
                add_node(services[port], f"{port}/tcp", "service")
                add_edge("target", services[port], "exposes")
            parent = services[port]
        elif str(finding.get("vector")) == "dns" and "dns" in nodes:
            parent = "dns"
        elif ("web" in nodes
              and str(finding.get("vector")) in ("web", "api", "recon")):
            parent = "web"
        add_edge(parent, node_id, "affected by")

        impact_id, impact_label = _impact_for(finding)
        add_node(impact_id, impact_label, "impact")
        add_edge(node_id, impact_id, "enables")

    incoming: dict[str, int] = {}
    for source, dest, label in edges:
        if label in ("affected by", "enables"):
            incoming[source] = incoming.get(source, 0) + 1
    chokepoints = []
    for node_id, count in sorted(incoming.items(),
                                 key=lambda item: (-item[1], item[0])):
        node = nodes.get(node_id) or {}
        if node.get("kind") not in ("service", "impact", "web"):
            continue
        chokepoints.append({
            "id": node_id,
            "label": str(node.get("label") or node_id),
            "kind": node.get("kind"),
            "findings": count,
        })
    chokepoints = chokepoints[:8]

    paths = []
    for finding in mapped[:8]:
        finding_id = f"f-{_slug(finding.get('id') or 'finding')}"
        parent = next((s for s, d, label in edges
                       if d == finding_id and label == "affected by"), None)
        impact = next((d for s, d, label in edges
                       if s == finding_id and label == "enables"), None)
        if parent and impact:
            paths.append(
                f"{nodes[parent]['label']} -> {nodes[finding_id]['label']} "
                f"-> {nodes[impact]['label']}")

    graph = {
        "target": target,
        "nodes": list(nodes.values()),
        "edges": [{"source": s, "target": d, "label": label}
                  for s, d, label in edges],
        "chokepoints": chokepoints,
        "paths": paths,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "findings_total": len(findings),
            "findings_mapped": len(mapped),
            "services": sum(1 for n in nodes.values()
                            if n["kind"] == "service"),
            "impacts": sum(1 for n in nodes.values()
                           if n["kind"] == "impact"),
            "kev_findings": sum(1 for f in findings if f.get("kev")),
        },
        "disclaimer": ("Attack paths are a deterministic projection of the "
                       "observed findings, not proof of exploitability."),
    }
    graph["dot"] = to_dot(graph)
    return graph


def to_dot(graph: dict) -> str:
    lines = [
        "digraph smartvapt {",
        "  graph [rankdir=LR, bgcolor=\"transparent\", pad=0.3, "
        "nodesep=0.45, ranksep=0.8];",
        "  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", "
        "fontsize=10, color=\"#94a3b8\"];",
        "  edge [color=\"#94a3b8\", fontname=\"Helvetica\", fontsize=8, "
        "arrowsize=0.7];",
    ]
    for node in graph.get("nodes") or []:
        fill = (SEVERITY_FILL.get(node.get("severity"), KIND_FILL.get(
            node.get("kind"), "#e2e8f0")))
        border = {"critical": "#dc2626", "high": "#ea580c",
                  "medium": "#ca8a04", "low": "#16a34a"}.get(
                      node.get("severity"), "#64748b")
        lines.append(
            f'  "{_dot_escape(node["id"])}" [label="'
            f'{_dot_escape(node["label"])}", fillcolor="{fill}", '
            f'color="{border}"];')
    for edge in graph.get("edges") or []:
        lines.append(
            f'  "{_dot_escape(edge["source"])}" -> '
            f'"{_dot_escape(edge["target"])}" '
            f'[label="{_dot_escape(edge["label"])}"];')
    lines.append("}")
    return "\n".join(lines)
