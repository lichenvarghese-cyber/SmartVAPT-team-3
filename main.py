import os
import time

import pandas as pd
import streamlit as st

import exporters
from ai_engine import AIEngine, check_engine
from api_scanner import APIScanner
from command_tracker import tracker
from compliance_mapper import compliance_rows, summarize as summarize_compliance
from config import SLM_BASE_URL, SLM_MODEL, SLM_PROVIDER
from eta_estimator import ScanEta, fmt_eta
from evidence import EvidenceStore, new_scan_id
from findings import FindingSet
from geo_locator import GeoLocator
from infrastructure_mapper import (InfrastructureMapper, apply_override,
                                   default_guardrails)
from network_scanner import NetworkScanner
from nuclei_scanner import NucleiScanner
from report_gen import generate_report
from scoring import enrich_findings
from subdomain_scanner import SubdomainScanner
from verification import apply_verification
from verify_fix import verify_fix
from web_scanner import DNSScanner, WebScanner, parse_auth_headers

st.set_page_config(page_title="SmartVAPT", page_icon="SHIELD", layout="wide")
st.title("SmartVAPT")
st.caption("Tri-Vector Attack Surface Analyzer & AI Reporting Engine")
st.markdown("---")


def _ingest_findings(finding_set, items):
    """Add scanner findings to the FindingSet.

    Scanners are inconsistent: some return ``Finding`` dataclasses (DNS, TLS,
    Nuclei) and some return already-serialized dicts (network, API). Accept
    both instead of silently dropping the dataclass ones.
    """
    from findings import Finding
    for item in items or []:
        try:
            if isinstance(item, Finding):
                finding_set.add(item)
            elif isinstance(item, dict):
                finding_set.add(Finding(**{
                    k: v for k, v in item.items()
                    if k in Finding.__dataclass_fields__}))
            else:
                finding_set.add(item)
        except Exception as fe:
            st.warning(f"Skipped malformed finding: {fe}")

# Model used for this run's AI narrative (the sidebar can override it).
slm_choice = SLM_MODEL


@st.fragment
def _verify_fix_panel(findings_list, scan_target, guardrails, auth_headers,
                      scan_id):
    """Fragment: per-finding Verify Fix. Only this panel reruns on click, so
    the scan results around it stay on screen."""
    findings_list = [f for f in (findings_list or []) if isinstance(f, dict)]
    if not findings_list:
        st.caption("No findings available to re-test.")
        return
    store_key = f"fix_verification_{scan_id}"
    outcomes = st.session_state.setdefault(store_key, {})
    labels = [f"{f.get('id', '?')} — {str(f.get('title', ''))[:80]}"
              for f in findings_list]
    chosen = st.selectbox("Finding to re-test", labels,
                          key=f"verify_fix_select_{scan_id}")
    index = labels.index(chosen) if chosen in labels else 0
    finding = findings_list[index]
    finding_id = str(finding.get("id", ""))

    if st.button("🔁 Re-run check", key=f"verify_fix_button_{scan_id}",
                 use_container_width=True):
        with st.spinner("Re-running a single read-only check..."):
            outcomes[finding_id] = verify_fix(
                finding, scan_target=scan_target,
                guardrails=guardrails or {},
                auth_headers=auth_headers or {})
        last = st.session_state.get("last_results") or {}
        last["fix_verification"] = list(outcomes.values())
        st.session_state["last_results"] = last

    outcome = outcomes.get(finding_id)
    if not outcome:
        st.caption("Run the check to compare the current state with the "
                   "original finding. Requests are read-only and bounded.")
        return
    icons = {"fixed": "✅", "still_present": "❌",
             "inconclusive": "⚠️", "skipped": "⏭️"}
    status = str(outcome.get("status", "inconclusive"))
    icon = icons.get(status, "⚠️")
    st.markdown(f"{icon} **{status.replace('_', ' ').title()}** — "
                f"{outcome.get('detail', '')}")
    st.caption(f"Check `{outcome.get('check', '?')}` · "
               f"{outcome.get('duration_ms', 0)} ms · "
               f"{outcome.get('checked_at', '')}")
    if outcome.get("observed"):
        with st.expander("Observed data"):
            st.json(outcome["observed"])


@st.cache_data(ttl=30, show_spinner=False)
def _slm_status(provider: str, base_url: str, model: str) -> dict:
    """Cached (30s) reachability probe for the local SLM endpoint."""
    return check_engine(provider=provider, base_url=base_url, model=model)


with st.sidebar:
    st.header("Scan Configuration")
    # --- AI engine status (local SLM) ---
    _status = _slm_status(SLM_PROVIDER, SLM_BASE_URL, SLM_MODEL)
    if _status.get("reachable") and _status.get("model_installed"):
        _badge = "🟢 AI ready"
    elif _status.get("reachable"):
        _badge = "🟡 AI model missing"
    else:
        _badge = "🔴 AI offline"
    with st.expander(f"{_badge} — AI report engine",
                     expanded=not _status.get("reachable")):
        st.caption(f"Provider: `{_status['provider']}` · "
                   f"Endpoint: `{_status['base_url']}`")
        if _status.get("reachable"):
            _models = _status.get("models") or []
            if _models:
                _prev = st.session_state.get("slm_model")
                if _prev in _models:
                    _idx = _models.index(_prev)
                elif SLM_MODEL in _models:
                    _idx = _models.index(SLM_MODEL)
                else:
                    _idx = 0
                slm_choice = st.selectbox(
                    "Model", _models, index=_idx,
                    help="Local model used to write the AI narrative. "
                         "Runs on this machine; scan data never leaves it.")
                st.session_state["slm_model"] = slm_choice
            else:
                st.warning("The server is running but no models are installed.")
                st.code("ollama pull phi3:mini", language="bash")
            if _models and not _status.get("model_installed"):
                st.info(f"Configured model `{SLM_MODEL}` is not installed — "
                        f"using `{slm_choice}`.")
            if _models:
                st.caption("Prompts and findings stay on this host.")
        else:
            st.error("Not running — reports fall back to a deterministic "
                     "summary instead of an AI narrative.")
            st.caption(f"`{_status.get('error')}`")
            st.code("curl -fsSL https://ollama.com/install.sh | sh\n"
                    "ollama serve   # or: sudo systemctl start ollama\n"
                    "ollama pull phi3:mini", language="bash")
        if st.button("Re-check AI engine", key="slm_recheck",
                     use_container_width=True):
            _slm_status.clear()
            st.rerun()
    target = st.text_input("Target (IP / domain / URL)", value="scanme.nmap.org")
    scan_network = st.checkbox("Network Scan (Nmap + vulners)", value=True)
    scan_web = st.checkbox("Web App Audit (headers + dirs)", value=True)
    scan_dns = st.checkbox("DNS / Email Security (SPF + DMARC)", value=True)
    scan_geo = st.checkbox("IP Geolocation & Hosting Lookup", value=True,
                           help="Resolve the target to its IP(s) and show "
                                "where they are located (country/city) and "
                                "which hosting provider the website is set "
                                "up on (ISP / org / ASN). Uses free public "
                                "GeoIP APIs; private IPs are never sent out.")
    scan_guardrails = st.checkbox("Provider-aware safety guardrails", value=True,
                                  help="Classify the host/CDN/cloud/PaaS and "
                                       "automatically switch to passive or "
                                       "throttled scanning when appropriate. "
                                       "Also collects public RDAP/BGP/abuse "
                                       "contacts and security.txt.")
    guardrail_override = st.checkbox(
        "Override guardrails (authorized targets only)", value=False,
        help="Re-enables active scanning when a CDN/WAF or shared host was "
             "detected. Only use with written authorization; the override "
             "still keeps concurrency and request rates low.")
    st.markdown("**Extended vectors**")
    ports_mode = st.radio("Port selection",
                          ["Top 1000 most-used ports of all 65535 (recommended)",
                           "Nmap Top 100 ports (quick)",
                           "Ports 1-1000 (full low range)",
                           "Custom range / list"],
                          horizontal=False,
                          help="The recommended preset scans nmap's Top 1000 "
                               "most famous/used ports across the entire "
                               "65535-port space (--top-ports 1000) instead "
                               "of a sequential 1-1000 sweep; 'Ports 1-1000' "
                               "sweeps the whole 1-1000 range (-p 1-1000); "
                               "custom accepts e.g. 80,443,8000-9000")
    if ports_mode.startswith("Top 1000"):
        ports = "top1000"
    elif ports_mode.startswith("Nmap Top 100 "):
        ports = "top100"
    elif ports_mode.startswith("Ports 1-1000"):
        ports = "1-1000"
    else:
        ports = st.text_input("Custom port range", value="80,443,8080",
                              placeholder="e.g. 80,443,3000-4000 or 1-1000",
                              key="custom_ports")
    scan_nuclei = st.checkbox("Nuclei template scan", value=True,
                              help="Requires the 'nuclei' binary; skipped "
                                   "gracefully if absent. Enabled by default.")
    scan_sub = st.checkbox("Subdomain enum + takeover check", value=False,
                           help="crt.sh + DNS brute force; detects dangling CNAMEs (no takeover attempted)")
    scan_api = st.checkbox("API security checks", value=False,
                           help="Swagger/GraphQL/JWT/rate-limit smoke tests (OWASP API Top 10)")
    nuclei_rl = st.slider("Nuclei rate limit (req/s)", 1, 50, 10,
                          help="Keep low to avoid overloading the target")
    baseline_mode = st.toggle("Baseline / diff mode", value=False,
                              help="Compare this scan with a saved baseline and optionally save a new one")
    baseline_path = st.text_input("Baseline file", value="baseline.json",
                                  disabled=not baseline_mode,
                                  help="One file per target/environment; "
                                       "used for the NEW/FIXED/UNCHANGED diff")
    # --- New: finding filters ---
    with st.expander("Filter findings"):
        filter_severity = st.multiselect("Severity", ["critical", "high", "medium", "low", "info"],
                                         default=["critical", "high", "medium", "low", "info"],
                                         help="Show only these severities in the report and findings list (leave empty to keep all)")
        filter_vector = st.multiselect("Vector", ["network", "web", "dns", "api", "recon"],
                                       default=["network", "web", "dns", "api", "recon"],
                                       help="Show only these attack vectors (leave empty to keep all)")
    # --- New: report section toggles ---
    with st.expander("Report sections"):
        include_exec_summary = st.checkbox("Executive summary", value=True)
        include_top_findings = st.checkbox("Top findings", value=True)
        include_pentest_details = st.checkbox("Pen-test details & exploitation options", value=True)
        include_tech_remediation = st.checkbox("Technical remediation", value=True)
        include_appendix = st.checkbox("Appendix (scan details)", value=True)
    with st.expander("Authenticated scan (optional)"):
        auth_headers_raw = st.text_area(
            "HTTP headers sent with every web/API/Nuclei request",
            value="", height=110,
            placeholder="Cookie: sessionid=abc123\nAuthorization: Bearer eyJ...",
            help="One 'Name: value' per line. Lets you scan behind login "
                 "(session cookies, bearer tokens). Also forwarded to "
                 "gobuster (-c/-H) and nuclei (-H). Do not commit secrets.")
    # --- New: Remediation tracker ---
    # NOTE: the sidebar is rendered *before* the scan block, so it must never
    # touch the local `results` variable (it only exists inside `if run:`).
    # The last scan's findings are persisted in st.session_state after every
    # scan and read back here, so the tracker also works on a fresh page load.
    with st.expander("Remediation tracker"):
        st.caption("Track which findings have been fixed across scans.")
        if "remediation_tracker" not in st.session_state:
            st.session_state.remediation_tracker = {}  # {finding_id: "fixed"/"pending"}
        last_findings = st.session_state.get("last_findings") or []
        if not last_findings:
            st.caption("Run a scan to populate the tracker.")
        for f in last_findings:
            fid = str(f.get("id", ""))
            if not fid:
                continue
            sev = str(f.get("severity", "info")).upper()
            title = str(f.get("title", "Finding"))
            prev = st.session_state.remediation_tracker.get(fid, "pending")
            col1, col2 = st.columns([4, 1.2])
            with col1:
                st.markdown(f"**[{sev}]** {title}  \n`{fid}`")
            with col2:
                status = st.selectbox(
                    "Status", ["pending", "fixed"],
                    index=1 if prev == "fixed" else 0,
                    key=f"track_{fid}",
                    label_visibility="collapsed",
                    format_func=str.title,
                    help=f"Mark '{title}' as fixed or still pending")
            st.session_state.remediation_tracker[fid] = status
        if st.session_state.remediation_tracker:
            fixed = sum(1 for s in st.session_state.remediation_tracker.values() if s == "fixed")
            pending = sum(1 for s in st.session_state.remediation_tracker.values() if s == "pending")
            st.caption(f"Fixed: {fixed} · Pending: {pending}")
            if st.button("Clear tracker", key="clear_remediation_tracker"):
                for _k in [k for k in st.session_state if str(k).startswith("track_")]:
                    del st.session_state[_k]
                st.session_state.remediation_tracker = {}
                st.rerun()
    run = st.button("Run SmartVAPT Scan", use_container_width=True)
    live_output = st.sidebar.toggle("Live scan output", value=True,
                                    help="Stream nmap/gobuster progress in real time")
    st.markdown("---")
    st.caption("Only scan systems you are authorized to test.")


if run:
    if not target:
        st.error("Please enter a target.")
        st.stop()

    progress = st.progress(0, text="Initializing...")
    scan_id = new_scan_id()
    evidence = EvidenceStore(scan_id)
    findings = FindingSet()
    results = {"target": target, "scan_id": scan_id}
    auth_headers = parse_auth_headers(auth_headers_raw)
    if auth_headers:
        st.caption(f"Authenticated scan: {len(auth_headers)} custom header(s) "
                   f"({', '.join(auth_headers)}) will be sent to the target.")

    # ------------------------------------------------------------------
    # Time estimate for the loading page. Before anything runs we show a
    # conservative per-vector estimate (scaled by the port preset); as each
    # step finishes its real duration is recorded in eta_history.json so the
    # NEXT scan of this target estimates from measured averages. The ETA line
    # below the progress bar refreshes every second while the scan runs.
    # ------------------------------------------------------------------
    import threading as _threading

    eta = ScanEta(target, {"network": scan_network, "web": scan_web,
                           "dns": scan_dns, "nuclei": scan_nuclei,
                           "sub": scan_sub, "api": scan_api,
                           "geo": scan_geo}, ports=ports)
    est_area = st.empty()                 # headline + live countdown ticker
    bd_area = st.empty()                  # per-step breakdown (in expander)
    with st.expander("Estimated time per step"):
        bd_area.markdown("\n".join(eta.breakdown_lines()))

    progress_text = {"t": "Initializing"}
    _cur_step = {"label": None}
    _last_pct = {"v": 0}
    _scan_done = _threading.Event()

    def set_progress(pct: int, label: str | None = None):
        """Advance the bar and start/stop the matching ETA step."""
        if label:
            eta.start_step(label)
            _cur_step["label"] = label
        _last_pct["v"] = pct
        try:
            progress.progress(pct, text=f"{progress_text['t']} · {eta.remaining()}")
        except Exception:
            pass

    def show_step(pct: int, text: str, label: str | None = None):
        """Single entry point for every loading-page progress update: sets
        the current status text, marks the ETA step running, refreshes the
        bar with '~X remaining'."""
        progress_text["t"] = text
        set_progress(pct, label)

    def step_done(label: str):
        """Mark an ETA step finished (records its measured duration)."""
        eta.finish_step(label)
        if _cur_step["label"] == label:
            _cur_step["label"] = None
        try:
            bd_area.markdown("\n".join(eta.breakdown_lines()))
        except Exception:
            pass

    def _render_est():
        try:
            est_area.info(f"⏱ **{eta.headline()}** — {eta.remaining()}. "
                          "The estimate updates live as each step completes; "
                          "actual time depends on target responsiveness.")
        except Exception:
            pass      # widget context gone (script finished / session closed)

    def _ticker():
        while not _scan_done.wait(1.0):
            _render_est()
            try:
                progress.progress(_last_pct["v"],
                                  text=f"{progress_text['t']} · {eta.remaining()}")
                bd_area.markdown("\n".join(eta.breakdown_lines()))
            except Exception:
                break     # script moved past the widgets; stop refreshing

    _render_est()
    _threading.Thread(target=_ticker, daemon=True).start()

    # Real-time console: scanner status lines are appended as they arrive.
    if live_output:
        # Background-commands panel: shows the general overview of what is
        # currently running (e.g. "nmap port/vuln scan running on <target>")
        # plus every tool launched during this scan, refreshed in real time.
        cmds_area = st.empty()

        def render_commands():
            snap = tracker.snapshot()
            if not snap:
                return
            running = [s for s in snap if s["running"]]
            done = [s for s in snap if not s["running"]]
            header = (f"⚙️ **Background commands** — "
                      f"{len(running)} running, {len(done)} finished")
            rows = []
            for s in running + done:
                icon = "🟢" if s["running"] else ("✅" if s["state"] == "done" else "⚠️")
                state = "running…" if s["running"] else s["state"]
                rows.append(f"{icon} {s['desc']}  ·  {state}  ·  {s['elapsed']}s\n"
                            f"   `$ {s['cmd']}`")
            cmds_area.markdown(header + "\n\n" + "\n\n".join(rows))

        render_commands()

        log_area = st.empty()
        log_lines: list[str] = []

        def log_line(line: str):
            log_lines.append(line)
            if len(log_lines) > 200:          # keep the view bounded
                del log_lines[:-200]
            log_area.code("\n".join(log_lines))
            render_commands()                 # refresh the overview too
    else:
        def log_line(line: str):
            pass

        def render_commands():
            pass

    # Pause / stop controls for long-running scans. The callback below is
    # passed to every scanner progress_cb; scanners poll it per output line,
    # so pausing takes effect within one line of tool output.
    class ScanStopped(Exception):
        pass

    ctrl = {"paused": False, "stop": False}
    if live_output:
        pcol1, pcol2 = st.columns(2)
        with pcol1:
            pause_btn = st.button("⏸ Pause scan", use_container_width=True,
                                  key="pause_scan")
        with pcol2:
            stop_btn = st.button("⏹ Stop scan", use_container_width=True,
                                 key="stop_scan")
        if pause_btn:
            ctrl["paused"] = not ctrl["paused"]
            (st.warning("Scan paused — press again to resume.")
             if ctrl["paused"] else st.success("Scan resumed."))
        if stop_btn:
            ctrl["stop"] = True
            st.error("Stop requested — finishing current step, then aborting.")

    def gated_log(line: str):
        """progress_cb wrapper: streams output, honours pause/stop requests."""
        import time as _t
        log_line(line)
        while ctrl["paused"] and not ctrl["stop"]:
            _t.sleep(0.5)
        if ctrl["stop"]:
            raise ScanStopped("Scan stopped by user")

    run_cb = gated_log if live_output else None
    scan_stopped = False

    def stop_requested() -> bool:
        """Check the shared stop flag between steps (works even when the
        live console is off, so long as a step has run at least once)."""
        return scan_stopped or ctrl.get("stop", False)

    # ----------------------------------------------------------------
    # 0) GEOLOCATION / HOSTING LOOKUP
    #    Resolve the target to its IP(s), find where each IP is located
    #    (country/region/city) and where the website is set up (hosting
    #    provider / ISP / ASN + web server port). Non-intrusive: only
    #    public GeoIP APIs, no traffic to the target beyond one HEAD/GET.
    # ----------------------------------------------------------------
    if scan_geo and not scan_stopped:
        show_step(5, "Looking up target IP location & hosting...",
                  "Geolocation lookup")
        try:
            geo_result = GeoLocator(target, evidence=evidence).locate()
            results["geo"] = geo_result
        except Exception as e:
            results["geo"] = {"error": str(e)}
        step_done("Geolocation lookup")
    else:
        results["geo"] = {}

    # ----------------------------------------------------------------
    # 0b) PROVIDER INTELLIGENCE & SCAN GUARDRAILS
    #     Classify the host/CDN/cloud/PaaS and decide whether active
    #     scanning is safe. CDN/WAF -> passive, shared hosting -> throttled,
    #     PaaS -> no OS-level CVE scanning. Pivots are suggestions only.
    # ----------------------------------------------------------------
    guardrails = default_guardrails(nuclei_rl)
    infrastructure: dict = {}
    if scan_guardrails and not scan_stopped:
        show_step(8, "Classifying provider & applying guardrails...",
                  "Provider guardrails")
        try:
            infrastructure = InfrastructureMapper(
                target, evidence=evidence).analyze(
                    results.get("geo") if scan_geo else None,
                    requested_nuclei_rate=nuclei_rl)
            if guardrail_override:
                infrastructure = apply_override(
                    infrastructure, requested_nuclei_rate=nuclei_rl)
            results["infrastructure"] = infrastructure
            guardrails = infrastructure.get("guardrails") or guardrails
            mode = infrastructure.get("recommended_mode")
            reason = infrastructure.get("mode_reason") or ""
            provider_label = infrastructure.get("provider_label") or "unknown provider"
            if mode == "passive":
                st.warning(f"🛡️ Passive mode ({provider_label}) — {reason}")
            elif mode == "throttled":
                st.warning(f"🐢 Throttled mode ({provider_label}) — {reason}")
            elif infrastructure.get("paas_detected"):
                st.info(f"☁️ PaaS focus ({provider_label}) — {reason}")
            if infrastructure.get("guardrail_override"):
                st.warning("⚠️ Provider guardrails were overridden by the "
                           "operator. Active scanning is only permitted on "
                           "targets you are explicitly authorized to test.")
            if infrastructure.get("warnings"):
                with st.expander("Provider warnings & dynamic focus"):
                    for warning in infrastructure["warnings"]:
                        st.warning(warning)
                    for focus in infrastructure.get("dynamic_focus") or []:
                        st.markdown(f"- {focus}")
        except Exception as e:
            results["infrastructure"] = {"error": str(e)}
            st.warning(f"Provider classification skipped: {e}")
        step_done("Provider guardrails")
    else:
        results["infrastructure"] = {}
    results["guardrails"] = guardrails

    # ----------------------------------------------------------------
    # 1) NETWORK
    # ----------------------------------------------------------------
    if scan_network and not scan_stopped and not guardrails.get("allow_network", True):
        results["network"] = {
            "skipped": "provider_guardrail",
            "reason": ("Network/OS scanning disabled by provider guardrails "
                       f"({infrastructure.get('provider') or 'unknown provider'})."),
        }
        st.info("Network scan skipped by provider guardrails. Enable the "
                "override only if you are authorised to test this host.")
    elif scan_network and not scan_stopped:
        show_step(15, "Running network scan (Nmap + vulners)...",
                  "Network scan (Nmap)")
        try:
            net_target = (target.replace("http://", "")
                                .replace("https://", "")
                                .split("/")[0].split(":")[0])
            ns = NetworkScanner(net_target, evidence=evidence)

            def _net_cb(line: str):
                render_commands()   # refresh overview on every nmap status line
                run_cb(line) if run_cb else None

            net_result = ns.scan(ports=ports, os_detect=False,
                                 progress_cb=_net_cb if live_output else None,
                                 stop_flag=ctrl)
            results["network"] = net_result
            # Record the exact port selection for the report ("top1000" or a
            # literal range like "1-1000").
            results["ports_requested"] = ports
            _ingest_findings(findings, net_result.get("findings", []))
        except (ScanStopped, RuntimeError) as e:
            # ScanStopped -> user stop via progress callback;
            # RuntimeError("Scan stopped by user") -> raised by the scanner
            # when it polls the stop flag. Any other RuntimeError is reported
            # as a genuine error below.
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["network"] = {"stopped": True}
            else:
                results["network"] = {"error": str(e)}
        except Exception as e:
            results["network"] = {"error": str(e)}
        step_done("Network scan (Nmap)")
    else:
        results["network"] = {}

    # ----------------------------------------------------------------
    # 2) WEB
    # ----------------------------------------------------------------
    http_services = (results.get("network", {}) or {}).get("http_services") or []
    if not http_services and scan_web:
        # Network scan unavailable/failed -> probe common HTTP ports directly
        # so gobuster still targets a confirmed HTTP port (nmap-equivalent).
        from portsets import probe_http_ports
        net_host = (target.replace("http://", "").replace("https://", "")
                    .split("/")[0].split(":")[0])
        http_services = probe_http_ports(net_host)
        if http_services:
            st.caption(f"HTTP discovered on port {http_services[0]['port']} "
                       f"via direct probe ({http_services[0]['url']}).")
    if scan_web and not scan_stopped:
        show_step(45, "Auditing web application...", "Web application audit")
        try:
            ws = WebScanner(target, evidence=evidence, auth_headers=auth_headers)
            # Follow nmap -sV: if HTTP was detected on a non-default port,
            # re-point the whole web audit (headers/dirs/TLS/...) at it.
            http_services = (results.get("network", {}) or {}).get("http_services") or []
            if http_services:
                det_url = http_services[0].get("url") or ""
                # Always sync port/service metadata with nmap -sV observations
                # so every web finding carries the accurate port/service.
                ws.set_target(det_url,
                              port=http_services[0].get("port"),
                              service=http_services[0].get("service"))
            web_result = {
                "headers": ws.check_headers(),
                "technologies": ws.detect_technologies(),
                "directories": (ws.gobuster_scan(
                    progress_cb=run_cb, stop_flag=ctrl,
                    http_services=http_services,
                    threads=guardrails.get("gobuster_threads", 20),
                    delay=guardrails.get("gobuster_delay", ""),
                    passive=not guardrails.get("allow_directory_bruteforce", True))
                    if guardrails.get("allow_directory_bruteforce", True)
                    else {"target": ws.target, "found": [], "findings": [],
                          "skipped": "provider_guardrail",
                          "error": "Directory brute-forcing disabled by provider guardrails."}),
                "tls": ws.analyze_tls(),
                "robots_sitemap": ws.fetch_robots_sitemap(),
                "sensitive_paths": (ws.probe_sensitive_paths(
                    request_delay=guardrails.get("request_delay", 0.0))
                    if guardrails.get("allow_sensitive_paths", True)
                    else {"found": [], "findings": [], "discarded": [],
                          "skipped": "provider_guardrail",
                          "error": "Sensitive-path probing disabled by provider guardrails."}),
                "redirects": ws.analyze_redirects(),
            }
            results["web"] = web_result
            results["web_audited_url"] = ws.target
            # Always sync port/service metadata with nmap -sV observations
            # so every web finding carries the accurate port/service.
            for key in ("headers", "directories", "tls",
                        "robots_sitemap", "sensitive_paths", "redirects"):
                _ingest_findings(findings,
                                 web_result.get(key, {}).get("findings", []))
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["web"] = {"stopped": True}
            else:
                results["web"] = {"error": str(e)}
        except Exception as e:
            results["web"] = {"error": str(e)}
        step_done("Web application audit")
    else:
        results["web"] = {}

    # ----------------------------------------------------------------
    # 3) DNS
    # ----------------------------------------------------------------
    if scan_dns and not scan_stopped:
        show_step(70, "Checking SPF / DMARC...", "DNS / email security")
        try:
            domain = (target.replace("http://", "")
                            .replace("https://", "")
                            .split("/")[0].split(":")[0])
            ds = DNSScanner(domain, evidence=evidence)
            dns_result = ds.check_email_security()
            results["dns"] = dns_result
            _ingest_findings(findings, dns_result.get("findings", []))
        except Exception as e:
            results["dns"] = {"error": str(e)}
        step_done("DNS / email security")
    else:
        results["dns"] = {}

    # ----------------------------------------------------------------
    # 3b) NUCLEI (extended web vector)
    # ----------------------------------------------------------------
    if scan_nuclei and not scan_stopped and not guardrails.get("allow_nuclei", True):
        results["nuclei"] = {
            "skipped": "provider_guardrail",
            "available": False,
            "matched": [], "findings": [],
            "error": "Nuclei disabled by provider guardrails (passive mode).",
        }
        st.info("Nuclei skipped by provider guardrails (passive mode).")
    elif scan_nuclei and not scan_stopped:
        show_step(74, "Running Nuclei template scan...", "Nuclei templates")
        try:
            nuc_target = ((results.get("web") or {}).get("directories") or {}).get("target") \
                or (results.get("network") or {}).get("primary_http_url") or target
            effective_rl = min(int(nuclei_rl),
                               int(guardrails.get("nuclei_rate_limit", nuclei_rl)))
            nsc = NucleiScanner(nuc_target, evidence=evidence,
                                rate_limit=effective_rl,
                                auth_headers=auth_headers)
            nuc_result = nsc.scan(progress_cb=run_cb, stop_flag=ctrl)
            results["nuclei"] = nuc_result
            _ingest_findings(findings, nuc_result.get("findings", []))
            if not nuc_result.get("available"):
                st.info(f"Nuclei skipped — {nuc_result.get('error','unavailable')}")
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["nuclei"] = {"stopped": True}
            else:
                results["nuclei"] = {"error": str(e)}
        except Exception as e:
            results["nuclei"] = {"error": str(e)}
        step_done("Nuclei templates")
    else:
        results["nuclei"] = {}

    # ----------------------------------------------------------------
    # 3c) SUBDOMAIN ENUM + TAKEOVER (recon vector)
    # ----------------------------------------------------------------
    if scan_sub and not scan_stopped:
        show_step(78, "Enumerating subdomains / takeover checks...",
                  "Subdomain enumeration")
        try:
            domain = (target.replace("http://", "")
                            .replace("https://", "")
                            .split("/")[0].split(":")[0])
            ssc = SubdomainScanner(domain, evidence=evidence)
            sub_result = ssc.enumerate(progress_cb=run_cb, stop_flag=ctrl)
            results["subdomains"] = sub_result
            _ingest_findings(findings, sub_result.get("findings", []))
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["subdomains"] = {"stopped": True}
            else:
                results["subdomains"] = {"error": str(e)}
        except Exception as e:
            results["subdomains"] = {"error": str(e)}
        step_done("Subdomain enumeration")
    else:
        results["subdomains"] = {}

    # ----------------------------------------------------------------
    # 3d) API SECURITY CHECKS
    # ----------------------------------------------------------------
    if scan_api and not scan_stopped and not guardrails.get("allow_api", True):
        results["api"] = {
            "skipped": "provider_guardrail",
            "endpoints": [], "findings": [],
            "errors": ["API checks disabled by provider guardrails (passive mode)."],
        }
        st.info("API checks skipped by provider guardrails (passive mode).")
    elif scan_api and not scan_stopped:
        show_step(81, "Running API security checks...", "API security checks")
        try:
            asc = APIScanner(target, evidence=evidence, auth_headers=auth_headers)
            api_result = asc.run_all(progress_cb=run_cb, stop_flag=ctrl)
            results["api"] = api_result
            _ingest_findings(findings, api_result.get("findings", []))
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["api"] = {"stopped": True}
            else:
                results["api"] = {"error": str(e)}
        except Exception as e:
            results["api"] = {"error": str(e)}
        step_done("API security checks")
    else:
        results["api"] = {}

    # ----------------------------------------------------------------
    # 4) AI
    # ----------------------------------------------------------------
    show_step(85, "AI is analyzing findings...", "AI analysis + report")
    # Deterministic CVSS normalization + remediation playbooks first, so the
    # report is complete even when the AI is unavailable.
    enriched = enrich_findings(findings.to_dict_list())

    # --- Apply UI finding filters before AI/report generation ---
    # filter_severity and filter_vector come from the sidebar expander;
    # narrowing here means the AI prompt, compliance summary, PDF and UI all
    # describe exactly the findings the user chose to report.
    try:
        fs = set(filter_severity) if 'filter_severity' in globals() else None
        fv = set(filter_vector) if 'filter_vector' in globals() else None
    except NameError:
        fs, fv = None, None
    if fs is not None or fv is not None:
        filt = enriched
        if fs:
            filt = [f for f in filt if str(f.get("severity") or "").lower() in fs]
        if fv:
            filt = [f for f in filt if str(f.get("vector") or "").lower() in fv]
        enriched = filt
    # Deterministic compliance posture is available even when the SLM is
    # offline and is passed to the model as grounding context.
    results["compliance"] = summarize_compliance(enriched)

    engine = None
    try:
        engine = AIEngine(model=slm_choice)
        ai_result = engine.analyze(enriched, results)
    except Exception as e:
        ai_result = {
            "executive_summary": f"AI unavailable: {e}",
            "overall_risk": "Unknown",
            "risk_score": 0,
            "top_findings": [],
            "technical_remediation": [],
            "compliance_summary": "",
            "conclusion": "",
        }
    # Ground every structured AI claim in this scan's findings and attach a
    # SHA-256 provenance record. Ungrounded claims are dropped.
    try:
        ai_result = apply_verification(enriched, ai_result, scan_id=scan_id)
        results["verification"] = ai_result.get("verification")
    except Exception as e:
        results["verification"] = {"verified": False, "status": "error",
                                   "error": str(e), "scan_id": scan_id}

    # --- New: apply UI finding filters ---
    # (Filters were applied before AI/report generation above; this block is
    # intentionally left out so the summary and the report cannot diverge.)
    results["findings"] = enriched
    # Persist the latest findings for the sidebar remediation tracker. The
    # sidebar renders on the next rerun and reads this from session state.
    st.session_state.last_findings = enriched
    st.session_state.last_scan_id = scan_id
    st.session_state.last_target = target

    # ----------------------------------------------------------------
    # 4b) BASELINE / DIFF
    # ----------------------------------------------------------------
    diff_summary = None
    if baseline_mode:
        base = exporters.load_baseline(baseline_path)
        if base:
            diff = exporters.diff_findings(base, enriched)
            results["diff"] = {k: v for k, v in diff.items()}
            diff_summary = exporters.format_diff_summary(diff)
        else:
            results["diff"] = None
            st.info(f"No baseline found at '{baseline_path}' yet — run the "
                    "scan, then click 'Save current scan as baseline' in the "
                    "Exports section to enable future diffs.")
    else:
        results["diff"] = None

    if scan_stopped:
        st.warning("⏹ Scan was stopped early — the report covers only the "
                   "vectors that completed before the stop request.")

    # ----------------------------------------------------------------
    # 5) PDF
    # ----------------------------------------------------------------
    progress_text["t"] = "Generating PDF report..."
    set_progress(95)
    pdf_path = f"SmartVAPT_{scan_id}.pdf"
    try:
        generate_report(results, ai_result, pdf_path,
                        include_exec_summary=include_exec_summary,
                        include_top_findings=include_top_findings,
                        include_pentest_details=include_pentest_details,
                        include_tech_remediation=include_tech_remediation,
                        include_appendix=include_appendix)
    except Exception as e:
        pdf_path = None
        st.warning(f"PDF generation failed: {e}")

    step_done("AI analysis + report")
    _scan_done.set()                    # stop the live ETA ticker
    total_elapsed = time.time() - eta.started
    planned = fmt_eta(eta.total_estimate())
    progress.progress(100, text=f"Scan complete — actual {fmt_eta(total_elapsed)} "
                                f"(planned ~{planned})")
    st.success(f"Scan completed for {target} in {total_elapsed:.0f}s — "
               f"{len(findings)} findings")

    # Make it explicit whether this report's narrative really came from the
    # local model or from the deterministic fallback.
    _ai_error = getattr(engine, "last_error", None)
    if engine is not None and not _ai_error:
        st.success(f"🤖 AI narrative generated locally with `{engine.model}` — "
                   "all prompts stayed on this machine.")
    else:
        st.warning(
            "🤖 AI narrative unavailable — this report uses the deterministic "
            "fallback summary."
            + (f" Reason: {_ai_error}." if _ai_error else "")
            + " Open **AI report engine (local SLM)** in the sidebar for setup."
        )

    # ----------------------------------------------------------------
    # RISK SUMMARY DASHBOARD
    # ----------------------------------------------------------------
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in enriched:
        counts[str(f.get("severity", "info")).lower()] = \
            counts.get(str(f.get("severity", "info")).lower(), 0) + 1
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Critical", counts["critical"])
    c2.metric("High",     counts["high"])
    c3.metric("Medium",   counts["medium"])
    c4.metric("Low",      counts["low"])
    c5.metric("Info",     counts["info"])

    if diff_summary:
        st.markdown(f"**Baseline diff:** {diff_summary}")
        d = results.get("diff") or {}
        if d.get("new"):
            with st.expander(f"{len(d['new'])} NEW findings since baseline"):
                st.dataframe(pd.DataFrame(d["new"])[[c for c in
                    ["id", "vector", "severity", "title", "target"]
                    if c in d["new"][0]]], use_container_width=True, hide_index=True)
        if d.get("fixed"):
            st.caption(f"✅ {len(d['fixed'])} finding(s) from the baseline are now fixed.")

    st.markdown("### Findings by Vector")
    vector_counts: dict = {}
    for f in enriched:
        v = str(f.get("vector", "other") or "other")
        vector_counts[v] = vector_counts.get(v, 0) + 1
    if vector_counts:
        vector_df = pd.DataFrame(
            [{"Vector": k, "Count": v} for k, v in sorted(vector_counts.items())])
        st.bar_chart(vector_df.set_index("Vector"))
    else:
        st.info("No findings to chart — nothing was detected in this scan.")

    st.subheader("Executive Summary")
    st.write(ai_result.get("executive_summary", "N/A"))
    verification = ai_result.get("verification") or {}
    if verification:
        ok = verification.get("verified")
        st.caption(
            f"{'✅' if ok else '⚠️'} AI data verification: "
            f"{verification.get('status', 'unknown').upper()} — "
            f"{verification.get('grounded_claims', 0)}/{verification.get('structured_claims', 0)} "
            f"structured claims matched this scan · "
            f"findings digest `{verification.get('data_sha256', 'N/A')[:12]}…`"
        )

    # ----------------------------------------------------------------
    # TABS
    # ----------------------------------------------------------------
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
        ["Network", "Web", "DNS", "Recon / API", "All Findings", "Location",
         "Provider & Compliance"])

    # ================== NETWORK TAB ==================
    with tab1:
        net = results.get("network", {}) or {}
        if net.get("error"):
            st.error(f"Network scan error: {net['error']}")
        else:
            s = net.get("summary", {})
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Open Ports", s.get("open_ports", 0))
            m2.metric("Total CVEs", s.get("total_cves", 0))
            m3.metric("High-Risk CVEs", s.get("critical", 0) + s.get("high", 0))
            m4.metric("Hosts Up", len(net.get("hosts", [])))

            os_matches = net.get("os_matches", [])
            if os_matches:
                st.markdown("#### Detected OS")
                os_df = pd.DataFrame(os_matches)
                keep = [c for c in ["host", "name", "accuracy"] if c in os_df.columns]
                if keep:
                    os_df = os_df[keep].rename(columns={
                        "host": "Host",
                        "name": "OS Guess",
                        "accuracy": "Accuracy (%)",
                    })
                    st.dataframe(os_df, use_container_width=True, hide_index=True)

            st.markdown("#### Open Ports & Services")
            rows = []
            for host in net.get("hosts", []):
                for p in host.get("ports", []):
                    rows.append({
                        "Host": host.get("ip"),
                        "Port": p.get("port"),
                        "Proto": p.get("protocol"),
                        "Service": p.get("service"),
                        "Product": p.get("product") or "-",
                        "Version": p.get("version") or "-",
                        "CVEs": len(p.get("cves", [])),
                    })
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("No open ports found in the scanned range.")

    # ================== WEB TAB ==================
    with tab2:
        web = results.get("web", {}) or {}
        if web.get("error"):
            st.error(f"Web scan error: {web['error']}")
        else:
            hdrs = web.get("headers", {}) or {}
            tls = web.get("tls", {}) or {}
            techs = (web.get("technologies", {}) or {}).get("technologies", [])
            dirs = (web.get("directories", {}) or {}).get("found", [])
            sens = (web.get("sensitive_paths", {}) or {}).get("found", [])

            w1, w2, w3, w4 = st.columns(4)
            w1.metric("Server", hdrs.get("server", "unknown"))
            w2.metric("Missing Headers", len(hdrs.get("missing", [])))
            w3.metric("Technologies", len(techs))
            w4.metric("Paths Found", len(dirs) + len(sens))

            st.markdown("#### HTTP Security Headers")
            hdr_rows = []
            for h in hdrs.get("present", []):
                hdr_rows.append({
                    "Header": h["header"],
                    "Status": "Present",
                    "Value": str(h.get("value", ""))[:60],
                })
            for h in hdrs.get("missing", []):
                hdr_rows.append({"Header": h, "Status": "MISSING", "Value": ""})
            if hdr_rows:
                st.dataframe(pd.DataFrame(hdr_rows),
                             use_container_width=True, hide_index=True)

            if techs:
                st.markdown("#### Detected Technologies")
                st.dataframe(pd.DataFrame(techs),
                             use_container_width=True, hide_index=True)

            if tls.get("enabled"):
                st.markdown("#### TLS")
                cert = tls.get("cert", {})
                t1, t2, t3 = st.columns(3)
                t1.metric("TLS Version", cert.get("version", "-"))
                t2.metric("Cipher", (cert.get("cipher") or "-")[:24])
                t3.metric("Valid Until", cert.get("notAfter", "-"))

            if dirs:
                st.markdown(f"#### Discovered Directories ({len(dirs)})")
                st.dataframe(pd.DataFrame(dirs),
                             use_container_width=True, hide_index=True)

            if sens:
                st.markdown(f"#### Sensitive Paths Exposed ({len(sens)})")
                st.dataframe(pd.DataFrame(sens),
                             use_container_width=True, hide_index=True)
            # False-positive reduction transparency (soft-404 / MIME / signature)
            sp = web.get("sensitive_paths", {}) or {}
            base = sp.get("soft404_baseline") or {}
            disc = sp.get("discarded", [])
            if base:
                if base.get("detected"):
                    title_part = f", title {base.get('title')!r}" if base.get("title") else ""
                    st.caption(f"Soft-404 baseline: DETECTED "
                               f"({base.get('body_size')} bytes{title_part}) — "
                               f"{base.get('returned_200')}/{base.get('probed')} "
                               f"random paths returned HTTP 200.")
                else:
                    st.caption("Soft-404 baseline: not detected "
                               "(server returns real 404s for missing paths).")
            if disc:
                with st.expander(f"Filtered false positives ({len(disc)})"):
                    st.dataframe(
                        pd.DataFrame([{"path": d["path"], "status": d["status"],
                                       "size": d["size"],
                                       "Content-Type": d.get("content_type"),
                                       "Discard reason": d["reason"]} for d in disc]),
                        use_container_width=True, hide_index=True)

    # ================== DNS TAB ==================
    with tab3:
        dns = results.get("dns", {}) or {}
        if dns.get("error"):
            st.error(f"DNS scan error: {dns['error']}")
        else:
            spf = dns.get("spf", {}) or {}
            dmarc = dns.get("dmarc", {}) or {}

            d1, d2, d3 = st.columns(3)
            d1.metric("Domain", dns.get("domain", "-"))
            d2.metric("SPF", "Present" if spf.get("present") else "Missing")
            d3.metric("DMARC", "Present" if dmarc.get("present") else "Missing")

            st.markdown("#### SPF Record")
            if spf.get("present"):
                st.code(spf.get("record", ""), language="text")
            else:
                st.warning("No SPF record — email spoofing possible")

            st.markdown("#### DMARC Record")
            if dmarc.get("present"):
                st.code(dmarc.get("record", ""), language="text")
                st.caption(f"Policy: `{dmarc.get('policy', 'none')}`")
            else:
                st.warning("No DMARC record — CEO fraud / spoofing possible")

    # ================== RECON / API TAB ==================
    with tab4:
        nuc = results.get("nuclei", {}) or {}
        sub = results.get("subdomains", {}) or {}
        api = results.get("api", {}) or {}

        st.markdown("#### Nuclei Template Findings")
        if not (nuc.get("available") or nuc.get("matched")):
            st.info(nuc.get("error") or "Nuclei vector not run.")
        elif nuc.get("matched"):
            st.dataframe(pd.DataFrame(nuc["matched"]),
                         use_container_width=True, hide_index=True)
        else:
            st.success("Nuclei ran — no template matches.")

        st.markdown("#### Subdomains")
        subs = sub.get("subdomains", [])
        if subs:
            st.dataframe(pd.DataFrame(subs), use_container_width=True,
                         hide_index=True)
        elif sub.get("error"):
            st.error(f"Recon error: {sub['error']}")
        elif sub:
            st.info("No subdomains resolved.")

        st.markdown("#### Subdomain Takeover Risks")
        risks = sub.get("takeover_risks", [])
        if risks:
            st.error(f"{len(risks)} dangling CNAME(s) takeoverable:")
            st.dataframe(pd.DataFrame(risks), use_container_width=True,
                         hide_index=True)
        elif subs:
            st.success("No takeoverable records detected.")

        st.markdown("#### API Surface")
        eps = api.get("endpoints", [])
        if eps:
            st.dataframe(pd.DataFrame(eps), use_container_width=True,
                         hide_index=True)
        for err in api.get("errors", []):
            st.caption(f"API check note: {err}")
        if not api:
            st.info("API checks not run.")

    # ================== ALL FINDINGS TAB ==================
    with tab5:
        all_findings = enriched
        if all_findings:
            rows = []
            for f in all_findings:
                comp = f.get("compliance") or {}
                rows.append({
                    "ID": f.get("id", ""),
                    "Severity": str(f.get("severity", "")).upper(),
                    "Vector": f.get("vector", ""),
                    "Title": f.get("title", ""),
                    "Target": f.get("target", ""),
                    "OWASP": ", ".join(comp.get("owasp") or []),
                    "PCI-DSS": ", ".join(comp.get("pci_dss") or []),
                    "NIST CSF": ", ".join(comp.get("nist_csf") or []),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True,
                         hide_index=True)
            st.markdown("#### 🔁 Verify Fix")
            st.caption("Re-test one finding after remediation without "
                       "re-running the whole scan. Checks are read-only and "
                       "respect the provider guardrails.")
            _verify_fix_panel(all_findings, target,
                              results.get("guardrails") or {},
                              auth_headers, scan_id)
            with st.expander("Remediation playbooks"):
                for f in all_findings[:30]:
                    steps = f.get("remediation_steps") or []
                    if not steps:
                        continue
                    st.markdown(f"**[{str(f.get('severity','')).upper()}] "
                                f"{f.get('title','')}**")
                    for s in steps:
                        st.markdown(f"- {s}")
                    for cmds in (f.get("remediation_commands") or {}).values():
                        st.code("\n".join(cmds), language="text")
        else:
            st.info("No findings.")

    # ================== LOCATION TAB ==================
    with tab6:
        geo = results.get("geo", {}) or {}
        if not geo:
            st.info("Geolocation vector not run.")
        elif geo.get("error") and not geo.get("locations"):
            st.error(f"Geolocation error: {geo['error']}")
        else:
            primary = geo.get("primary") or {}
            ws = geo.get("web_server") or {}
            g1, g2, g3, g4 = st.columns(4)
            g1.metric("Hostname", geo.get("hostname", "-"))
            g2.metric("Resolved IPs", len(geo.get("resolved_ips", [])))
            g3.metric("Country", primary.get("country_code", "-") or "-")
            g4.metric("Web Port", ws.get("port", "-"))

            if geo.get("summary"):
                st.markdown(f"**📍 Where the target is hosted:** {geo['summary']}")

            locs = geo.get("locations", [])
            rows = [{
                "IP": l.get("ip"),
                "City": l.get("city", ""),
                "Region": l.get("region", ""),
                "Country": l.get("country", ""),
                "Lat/Lon": (f"{l.get('latitude')}, {l.get('longitude')}"
                            if l.get("found") else ""),
                "Timezone": l.get("timezone", ""),
                "ISP": l.get("isp", ""),
                "Organization (hosting)": l.get("organization", ""),
                "ASN": l.get("asn", ""),
                "Reverse DNS": l.get("reverse_dns", ""),
                "Source": l.get("source", ""),
                "Note": l.get("note") or l.get("error") or "",
            } for l in locs]
            if rows:
                st.markdown("#### IP Geolocation & Hosting Details")
                st.dataframe(pd.DataFrame(rows), use_container_width=True,
                             hide_index=True)
            else:
                st.warning(geo.get("error") or "No IPs resolved for this target.")

            st.markdown("#### Website Setup")
            if ws:
                w_loc = ", ".join(x for x in
                                  (primary.get("city"), primary.get("region"),
                                   primary.get("country")) if x)
                st.markdown(
                    f"- **URL served:** `{ws.get('url', '-')}` "
                    f"(port **{ws.get('port', '-')}**, "
                    f"HTTP status {ws.get('status', 'n/a')})\n"
                    f"- **Web server software:** `{ws.get('server') or 'unknown'}`\n"
                    f"- **Hosting provider:** "
                    f"`{primary.get('organization') or primary.get('isp') or 'unknown'}` "
                    f"({primary.get('asn') or 'no ASN'})\n"
                    f"- **Physical location:** `{w_loc or 'unknown'}`"
                    + (f"\n- **Timezone:** `{primary.get('timezone')}`"
                       if primary.get("timezone") else ""))
            else:
                st.info("Website endpoint details unavailable.")

    # ================== PROVIDER & COMPLIANCE TAB ==================
    with tab7:
        infra = results.get("infrastructure") or {}
        st.markdown("#### Provider intelligence")
        if infra.get("error"):
            st.error(f"Provider classification error: {infra['error']}")
        elif not infra:
            st.info("Provider mapping was not run. Enable **Provider-aware "
                    "safety guardrails** in the sidebar and re-scan.")
        else:
            p1, p2, p3, p4 = st.columns(4)
            p1.metric("Provider", infra.get("provider") or "-")
            p2.metric("Type", infra.get("provider_type_label") or "-")
            p3.metric("ASN", infra.get("asn") or "-")
            p4.metric("Scan mode",
                      str(infra.get("recommended_mode") or "-").title())
            if infra.get("geo_summary"):
                st.caption(f"Hosting summary: {infra['geo_summary']}")
            for warning in infra.get("warnings") or []:
                st.warning(warning)
            if infra.get("legal_notice"):
                st.info(infra["legal_notice"])
            st.markdown("##### Abuse & security contacts")
            contacts = infra.get("abuse_contacts") or []
            if contacts:
                st.write(" · ".join(f"`{c}`" for c in contacts))
            else:
                st.caption("No public abuse contact was found via RDAP or "
                           "security.txt. Use the ASN/RDAP lookup links below.")
            security = infra.get("security_txt") or {}
            if security.get("found"):
                st.caption(f"security.txt: `{security.get('url')}`"
                           + (f" · expires {security['expires']}"
                              if security.get("expires") else ""))
            with st.expander("Suggested pivot targets (never scanned automatically)"):
                pivots = infra.get("pivot_targets") or []
                if pivots:
                    st.code("\n".join(pivots), language="text")
                else:
                    st.caption("No public prefixes were derived.")
                for url in infra.get("pivot_lookup_urls") or []:
                    st.markdown(f"- [{url}]({url})")
                if infra.get("pivot_note"):
                    st.caption(infra["pivot_note"])
            st.markdown("##### Active guardrails")
            guard = infra.get("guardrails") or {}
            guard_rows = [
                {"Control": "Network / OS scan",
                 "Setting": "allowed" if guard.get("allow_network") else "skipped"},
                {"Control": "Nuclei templates",
                 "Setting": "allowed" if guard.get("allow_nuclei") else "skipped"},
                {"Control": "Directory brute-force",
                 "Setting": "allowed" if guard.get("allow_directory_bruteforce") else "skipped"},
                {"Control": "Sensitive-path probing",
                 "Setting": "allowed" if guard.get("allow_sensitive_paths") else "skipped"},
                {"Control": "API active checks",
                 "Setting": "allowed" if guard.get("allow_api") else "skipped"},
                {"Control": "Nuclei rate limit (req/s)",
                 "Setting": str(guard.get("nuclei_rate_limit", "-"))},
                {"Control": "Gobuster threads",
                 "Setting": str(guard.get("gobuster_threads", "-"))},
                {"Control": "Request delay (s)",
                 "Setting": str(guard.get("request_delay", 0))},
            ]
            st.dataframe(pd.DataFrame(guard_rows), use_container_width=True,
                         hide_index=True)
            if guard.get("overridden"):
                st.warning("Guardrails were overridden by the operator for "
                           "this scan. Confirm written authorization.")
            focus = infra.get("dynamic_focus") or []
            if focus:
                st.markdown("##### Dynamic focus for this provider")
                for item in focus:
                    st.markdown(f"- {item}")

        st.markdown("---")
        st.markdown("#### Compliance posture")
        comp = results.get("compliance") or {}
        if not comp:
            st.info("No compliance summary was generated for this scan.")
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Exposure index", f"{comp.get('exposure_index', 0)}/100")
            c2.metric("Risk band", comp.get("risk_band", "None"))
            c3.metric("Mapped findings", comp.get("mapped_findings", 0))
            sev = comp.get("severity_counts") or {}
            c4.metric("Critical + High",
                      int(sev.get("critical", 0)) + int(sev.get("high", 0)))
            st.info(comp.get("c_level_summary") or "No compliance summary.")
            for label, key in (("OWASP Top 10 (2021)", "owasp"),
                               ("PCI-DSS requirements", "pci_dss"),
                               ("NIST CSF controls", "nist_csf")):
                rows = compliance_rows(comp, key)
                with st.expander(f"{label} — {len(rows)} affected",
                                 expanded=(key == "owasp")):
                    if rows:
                        st.dataframe(pd.DataFrame(rows),
                                     use_container_width=True,
                                     hide_index=True)
                    else:
                        st.caption("No findings mapped to this framework.")
            st.caption(comp.get("disclaimer") or "")

    # ----------------------------------------------------------------
    # MULTI-FORMAT EXPORTS
    # ----------------------------------------------------------------
    st.markdown("---")
    st.subheader("Exports")
    e1, e2, e3, e4 = st.columns(4)
    base_name = f"SmartVAPT_{scan_id}"
    try:
        exporters.export_json(results, ai_result, f"{base_name}.json")
        exporters.export_html(results, ai_result, f"{base_name}.html")
        exporters.export_sarif(results, f"{base_name}.sarif")
    except Exception as e:
        st.warning(f"Export generation failed: {e}")
    for col, label, fname, mime in (
        (e1, "JSON", f"{base_name}.json", "application/json"),
        (e2, "HTML dashboard", f"{base_name}.html", "text/html"),
        (e3, "SARIF 2.1.0", f"{base_name}.sarif", "application/json"),
    ):
        with col:
            if os.path.exists(fname):
                with open(fname, "rb") as fh:
                    st.download_button(label, fh, file_name=fname, mime=mime,
                                       use_container_width=True)
    with e4:
        if baseline_mode and st.button("Save current scan as baseline",
                                       use_container_width=True):
            exporters.save_baseline(results, baseline_path)
            st.toast(f"Baseline saved to {baseline_path}")

    # ----------------------------------------------------------------
    # PDF DOWNLOAD
    # ----------------------------------------------------------------
    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            st.download_button(
                "Download PDF Report",
                f,
                file_name=os.path.basename(pdf_path),
                mime="application/pdf",
                use_container_width=True,
            )

    # Persist the finished scan so its summary survives sidebar interactions
    # (any widget change triggers a rerun where `run` is False).
    st.session_state["last_results"] = results
    st.session_state["last_ai_result"] = ai_result
    st.session_state["last_pdf_path"] = pdf_path
    st.session_state["last_auth_headers"] = auth_headers

else:
    last = st.session_state.get("last_results")
    if not last:
        st.info("Configure the scan in the sidebar and click Run SmartVAPT Scan.")
    else:
        findings_last = last.get("findings") or []
        st.subheader(f"Last scan — {last.get('target', '')}")
        st.caption(f"Scan ID `{last.get('scan_id', '')}` · "
                   f"{len(findings_last)} finding(s). Click **Run SmartVAPT Scan** "
                   "to refresh; these results are kept while you update the sidebar.")
        counts_last = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for f in findings_last:
            sev_last = str(f.get("severity", "info")).lower()
            counts_last[sev_last] = counts_last.get(sev_last, 0) + 1
        lc1, lc2, lc3, lc4, lc5 = st.columns(5)
        lc1.metric("Critical", counts_last["critical"])
        lc2.metric("High", counts_last["high"])
        lc3.metric("Medium", counts_last["medium"])
        lc4.metric("Low", counts_last["low"])
        lc5.metric("Info", counts_last["info"])

        tracker_state = st.session_state.get("remediation_tracker", {})
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows_last = [{
            "ID": f.get("id", ""),
            "Severity": str(f.get("severity", "")).upper(),
            "Vector": f.get("vector", ""),
            "Title": f.get("title", ""),
            "Target": f.get("target", ""),
            "Remediation": tracker_state.get(str(f.get("id", "")), "pending").title(),
        } for f in findings_last]
        rows_last.sort(key=lambda r: sev_rank.get(r["Severity"].lower(), 5))
        if rows_last:
            st.dataframe(pd.DataFrame(rows_last), use_container_width=True,
                         hide_index=True)
        st.markdown("#### 🔁 Verify Fix")
        st.caption("Re-test a finding from the last scan after applying "
                   "remediation. Checks are read-only and respect the "
                   "provider guardrails.")
        _verify_fix_panel(findings_last, last.get("target", ""),
                          last.get("guardrails") or {},
                          st.session_state.get("last_auth_headers") or {},
                          last.get("scan_id", ""))
        last_pdf = st.session_state.get("last_pdf_path")
        if last_pdf and os.path.exists(last_pdf):
            with open(last_pdf, "rb") as fh:
                st.download_button("Download PDF Report", fh,
                                   file_name=os.path.basename(last_pdf),
                                   mime="application/pdf")
