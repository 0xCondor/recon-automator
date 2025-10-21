# recon_automator/core.py
from typing import Dict, Any
from .scanners import (
    resolve_target,
    run_nmap_profile,
    enumerate_subdomains,
    virustotal_check,
    abuseipdb_check
)
from .report import risk_score  # compatibilità
# nuovo import
from .probes import probe_subdomains_sync, probe_host_sync
from .enrichers import (
    passive_crtsh,
    passive_ipinfo,
    passive_whois_domain,
    build_recon_graph,
    take_website_screenshot,
    build_security_scorecard,
    generate_suggestions
)

def run_scan(target: str, api_keys: dict = None, nmap_profile: str = "safe") -> Dict[str, Any]:
    api_keys = api_keys or {}
    ip = resolve_target(target)
    if not ip:
        return None

    # 1) Active: Nmap
    open_ports = run_nmap_profile(ip, profile=nmap_profile)
    subs = enumerate_subdomains(target)

    # 2) Threat intel via API (opzionali)
    vt = virustotal_check(ip, api_keys.get("vt")) if api_keys.get("vt") else None
    abuse = abuseipdb_check(ip, api_keys.get("abuse")) if api_keys.get("abuse") else None

    # 3) Passive Recon (no-touch)
    passive = {
        "ipinfo": passive_ipinfo(ip),
        "whois": passive_whois_domain(target),
        "crtsh_subdomains": passive_crtsh(target)[:50]  # safe limit
    }

    # 4) Web probes (best-effort)
    try:
        host_probes = probe_host_sync(target)
    except Exception:
        host_probes = []

    try:
        subs_probed = probe_subdomains_sync(subs)
    except Exception:
        # ensure we keep structure similar to original subs
        subs_probed = [{"subdomain": s.get("subdomain"), "ip": s.get("ip"), "probe": None} for s in subs]

    # build base report
    base_report = {
        "target": target,
        "ip": ip,
        "open_ports": open_ports,
        "subdomains": subs_probed,
        "virustotal": vt,
        "abuseipdb": abuse,
        "passive": passive,
        "web_probe": {"host_probes": host_probes}
    }

    # 5) Scorecard + suggestions
    scorecard = build_security_scorecard(base_report)
    base_report["scorecard"] = scorecard
    base_report["risk_score"] = scorecard.get("overall_score")  # retrocompatibilità
    base_report["suggestions"] = generate_suggestions(base_report)

    # 6) Artifacts: Recon Graph + Screenshot (best effort)
    artifacts = {}
    graph_path = build_recon_graph(base_report, out_dir="reports/graphs")
    if graph_path:
        artifacts["graph_png"] = graph_path
    snap_path = take_website_screenshot(target, out_dir="reports/screenshots")
    if snap_path:
        artifacts["screenshot"] = snap_path
    base_report["artifacts"] = artifacts

    return base_report
