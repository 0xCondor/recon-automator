# recon_automator/core.py
from typing import Dict, Any
from .scanners import (
    resolve_target,
    run_nmap_profile,
    enumerate_subdomains,
    virustotal_check,
    abuseipdb_check
)
from .report import risk_score  # ancora disponibile
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

    # 1) Active
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

    # Merge subdomains passivi con quelli “risolti” (solo unione nomi)
    crt_set = set(passive["crtsh_subdomains"] or [])
    if crt_set:
        known = set([s["subdomain"] for s in subs])
        new_only = crt_set - known
        # non risolviamo qui i nuovi (evitiamo troppe DNS query), li lasciamo in passive

    # 4) Scorecard + suggestions
    base_report = {
        "target": target,
        "ip": ip,
        "open_ports": open_ports,
        "subdomains": subs,
        "virustotal": vt,
        "abuseipdb": abuse,
        "passive": passive
    }
    scorecard = build_security_scorecard(base_report)
    base_report["scorecard"] = scorecard
    base_report["risk_score"] = scorecard.get("overall_score")  # per retrocompatibilità
    base_report["suggestions"] = generate_suggestions(base_report)

    # 5) Artifacts: Recon Graph + Screenshot (best effort)
    artifacts = {}
    graph_path = build_recon_graph(base_report, out_dir="reports/graphs")
    if graph_path:
        artifacts["graph_png"] = graph_path
    snap_path = take_website_screenshot(target, out_dir="reports/screenshots")
    if snap_path:
        artifacts["screenshot"] = snap_path
    base_report["artifacts"] = artifacts

    return base_report
