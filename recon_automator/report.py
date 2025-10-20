# recon_automator/report.py
import json
import os
from datetime import datetime
from typing import Dict, Any, List

HISTORY_FILE = os.path.join("reports", "history.json")

def print_report(report: Dict[str, Any]):
    if not report:
        print("Nessun report disponibile.")
        return
    print(f"\n--- Report per {report.get('target')} ---")
    print(f"IP: {report.get('ip')}")
    ops = report.get('open_ports')
    if ops is None:
        print("Porte aperte: (nmap non installato o errore nella scansione)")
    else:
        print("Porte aperte:", ", ".join(map(str, ops)) if ops else "Nessuna")
    print("Subdomains:")
    subs = report.get('subdomains') or []
    if subs:
        for s in subs:
            print(f" - {s['subdomain']} ({s['ip']})")
    else:
        print(" Nessuno")
    print("VirusTotal:", report.get('virustotal') if report.get('virustotal') else "Non eseguito")
    print("AbuseIPDB:", report.get('abuseipdb') if report.get('abuseipdb') else "Non eseguito")
    if "scorecard" in report:
        print(f"Security Score (overall): {report['scorecard'].get('overall_score')}")
    print("-------------------------\n")

def export_json(report: Dict[str, Any], filename: str):
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

def export_markdown(report: Dict[str, Any], filename: str):
    """
    Esporta un markdown con Executive Summary, Score Card tabellare,
    findings e remediation suggestions.
    """
    lines: List[str] = []
    lines.append(f"# Report — {report.get('target')}")
    lines.append(f"**IP:** {report.get('ip')}")
    lines.append(f"**Data:** {datetime.now().isoformat()}")

    # Executive Summary
    lines.append("\n## Executive Summary\n")
    overall = (report.get("scorecard") or {}).get("overall_score", report.get("risk_score", 0))
    if overall >= 70:
        lines.append(f"- **Rischio complessivo: ALTO** ({overall}/100). Intervento urgente raccomandato.")
    elif overall >= 40:
        lines.append(f"- **Rischio complessivo: MEDIO** ({overall}/100). Pianificare remediation.")
    else:
        lines.append(f"- **Rischio complessivo: BASSO** ({overall}/100). Continuare il monitoraggio.")

    # Score Card
    sc = report.get("scorecard")
    if sc:
        lines.append("\n## Security Score Card\n")
        lines.append("| Fattore | Valore | Peso | Rischio |")
        lines.append("|---|---:|:---:|:---:|")
        for f in sc.get("factors", []):
            lines.append(f"| {f['name']} | {f['value']} | {f['weight']} | {f['risk']} |")
        lines.append(f"\n**Overall Score:** {sc.get('overall_score')}/100")

    # Findings Tecnici
    lines.append("\n## Findings Tecnici\n")
    ops = report.get('open_ports')
    if ops is None:
        lines.append("- Nmap non installato o scansione non eseguita.")
    elif ops:
        for p in ops:
            lines.append(f"- Porta {p} aperta")
    else:
        lines.append("- Nessuna porta aperta trovata.")

    subs = report.get('subdomains') or []
    lines.append("\n## Subdomains")
    if subs:
        for s in subs:
            lines.append(f"- {s['subdomain']} ({s['ip']})")
    else:
        lines.append("- Nessuno")

    # Threat Intel
    lines.append("\n## Threat Intelligence")
    lines.append(f"- VirusTotal: {report.get('virustotal') if report.get('virustotal') else 'Non eseguito'}")
    lines.append(f"- AbuseIPDB: {report.get('abuseipdb') if report.get('abuseipdb') else 'Non eseguito'}")

    # Passive intel
    if report.get("passive"):
        p = report["passive"]
        lines.append("\n## Passive Recon")
        if p.get("ipinfo"):
            lines.append(f"- IPInfo: {p['ipinfo']}")
        if p.get("whois"):
            lines.append(f"- WHOIS: {p['whois']}")
        if p.get("crtsh_subdomains"):
            lines.append(f"- crt.sh subdomains (top): {len(p['crtsh_subdomains'])}")

    # Links a risorse generate
    if report.get("artifacts"):
        lines.append("\n## Artefatti")
        art = report["artifacts"]
        if art.get("graph_png"):
            lines.append(f"- Recon Graph: `{art['graph_png']}`")
        if art.get("screenshot"):
            lines.append(f"- Website Screenshot: `{art['screenshot']}`")

    # Remediation
    if report.get("suggestions"):
        lines.append("\n## Remediation suggerite")
        for s in report["suggestions"]:
            lines.append(f"- {s}")

    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

def risk_score(report: Dict[str, Any]) -> int:
    """
    (Mantieni se ti serve ancora altrove) — ma ora usiamo la scorecard come metrica principale.
    """
    ops = report.get('open_ports')
    abuse = (report.get('abuseipdb') or {}).get('score', 0)
    vt = report.get('virustotal') or {}
    rep = vt.get('reputation') if isinstance(vt, dict) else None

    score = 0
    if ops is None:
        score += 10
    else:
        score += min(40, (len(ops) * 6))
    if abuse >= 75:
        score += 30
    elif abuse >= 40:
        score += 15
    try:
        if rep is not None and rep != "N/A":
            if isinstance(rep, int) and rep >= 50:
                score += 20
            elif isinstance(rep, int) and rep >= 10:
                score += 10
            else:
                score += 5
    except:
        pass
    return max(0, min(100, score))

def append_history(report: Dict[str, Any]):
    os.makedirs(os.path.dirname(HISTORY_FILE) or ".", exist_ok=True)
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except:
            history = []

    summary = {
        "timestamp": datetime.now().isoformat(),
        "target": report.get("target"),
        "ip": report.get("ip"),
        "overall_score": (report.get("scorecard") or {}).get("overall_score", report.get("risk_score")),
        "open_ports": report.get("open_ports")
    }

    # diff semplice
    last_same = None
    for item in reversed(history):
        if item.get("target") == summary["target"]:
            last_same = item
            break
    diffs = {}
    if last_same:
        prev_ports = set(last_same.get("open_ports") or [])
        curr_ports = set(summary.get("open_ports") or [])
        added = sorted(list(curr_ports - prev_ports))
        removed = sorted(list(prev_ports - curr_ports))
        if added:
            diffs["ports_added"] = added
        if removed:
            diffs["ports_removed"] = removed

    summary["diff"] = diffs
    history.append(summary)

    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

    return summary
