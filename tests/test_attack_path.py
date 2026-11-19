"""Tests for the deterministic attack-path graph."""
from attack_path import build_attack_path, to_dot


def _results():
    return {
        "target": "example.com",
        "network": {"hosts": [{
            "ip": "192.0.2.10",
            "ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 22, "protocol": "tcp", "service": "ssh"},
            ],
        }]},
        "web": {"headers": {}},
        "web_audited_url": "http://example.com",
        "dns": {"domain": "example.com"},
        "findings": [
            {"id": "WEB-001", "vector": "web", "port": 80,
             "title": "Missing security header: Content-Security-Policy",
             "severity": "medium", "owasp": "A05:2021"},
            {"id": "DNS-001", "vector": "dns", "port": None,
             "title": "Missing SPF record", "severity": "high"},
            {"id": "NET-001", "vector": "network", "port": 22,
             "title": "OpenSSH CVE-2024-6387 regreSSHion",
             "severity": "high", "cve": "CVE-2024-6387", "kev": True},
        ],
    }


def test_graph_contains_assets_services_and_impacts():
    graph = build_attack_path(_results())
    ids = {node["id"] for node in graph["nodes"]}
    assert {"target", "dns", "web", "svc-80-tcp", "svc-22-tcp"} <= ids
    assert "f-WEB-001" in ids
    assert "impact-client" in ids
    assert "impact-email" in ids
    assert "impact-service" in ids
    assert graph["summary"]["findings_mapped"] == 3
    assert graph["summary"]["kev_findings"] == 1


def test_edges_link_target_to_services_and_findings():
    graph = build_attack_path(_results())
    edges = {(e["source"], e["target"], e["label"]) for e in graph["edges"]}
    assert ("target", "svc-80-tcp", "exposes") in edges
    assert ("svc-80-tcp", "web", "hosts") in edges
    assert ("svc-80-tcp", "f-WEB-001", "affected by") in edges
    assert ("dns", "f-DNS-001", "affected by") in edges
    assert ("f-WEB-001", "impact-client", "enables") in edges


def test_paths_and_chokepoints_are_deterministic():
    graph = build_attack_path(_results())
    assert graph["paths"]
    assert all(path.count("->") == 2 for path in graph["paths"])
    first = [c["id"] for c in graph["chokepoints"]]
    second = [c["id"] for c in build_attack_path(_results())["chokepoints"]]
    assert first == second
    assert any(c["id"] == "svc-80-tcp" for c in graph["chokepoints"])


def test_dot_escapes_quotes_and_newlines():
    results = _results()
    results["findings"][0]["title"] = 'Header "CSP"\nmissing'
    dot = to_dot(build_attack_path(results))
    assert dot.startswith("digraph smartvapt {")
    assert '\\"CSP\\"' in dot
    assert "\\nmissing" in dot


def test_graph_caps_findings():
    results = _results()
    results["findings"] = [
        {"id": f"WEB-{i:03d}", "vector": "web", "port": 80,
         "title": f"Finding {i}", "severity": "low"} for i in range(40)]
    graph = build_attack_path(results)
    assert graph["summary"]["findings_mapped"] == 30
    assert graph["summary"]["findings_total"] == 40


def test_empty_results_are_safe():
    graph = build_attack_path({})
    assert len(graph["nodes"]) == 1
    assert graph["edges"] == []
    assert graph["paths"] == []
    assert "digraph" in graph["dot"]
