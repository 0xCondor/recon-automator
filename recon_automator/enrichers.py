# recon_automator/enrichers.py
# Passive Recon + Snapshot + Recon Graph + Suggestions

import os
import json
import time
import socket
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional

from .utils import info, warn, err

# ─────────────────────────────────────────────────────────────
# Passive Recon: crt.sh (subdomains), ipinfo (ASN), whois (registrar / dates)

def passive_crtsh(domain: str, limit: int = 50) -> List[str]:
    """
    Ritorna una lista di subdomains (unici) estratti da crt.sh (passive DNS via certs).
    Non richiede API. Rate-limit "gentile".
    """
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=15, headers={"User-Agent": "ReconAutomator"})
        if r.status_code != 200:
            return []
        data = r.json()
        subs = set()
        for row in data[:limit]:
            name = row.get("name_value") or ""
            for candidate in name.split("\n"):
                c = candidate.strip().lower()
                if c.endswith("." + domain) or c == domain:
                    subs.add(c)
        return sorted(subs)
    except Exception:
        return []

def passive_ipinfo(ip: str) -> Optional[Dict[str, Any]]:
    """
    ASN / Country / Org via ipinfo.io (endpoint pubblico rate-limited).
    """
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "asn": (data.get("org") or "").split()[0] if data.get("org") else None,
                "org": data.get("org"),
                "country": data.get("country"),
                "city": data.get("city"),
                "loc": data.get("loc"),
            }
    except Exception:
        return None
    return None

def passive_whois_domain(domain: str) -> Optional[Dict[str, Any]]:
    """
    WHOIS domain (senza servizi a pagamento). Usa python-whois.
    """
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        return {
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
        }
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────
# Recon Graph: Graphviz (IP -> Subdomains -> Ports)

def build_recon_graph(report: Dict[str, Any], out_dir: str) -> Optional[str]:
    """
    Crea un grafo PNG in reports/graphs/target_timestamp.png
    Richiede 'graphviz' Python + binari graphviz installati.
    """
    try:
        from graphviz import Digraph
        os.makedirs(out_dir, exist_ok=True)
        target = report.get("target", "target")
        ip = report.get("ip", "ip")
        ports = report.get("open_ports") or []
        subs = report.get("subdomains") or []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        png_path = os.path.join(out_dir, f"graph_{target.replace('.', '_')}_{ts}.png")

        dot = Digraph(comment="Recon Graph", format="png")
        dot.attr(rankdir="LR", fontsize="10")

        # nodi
        dot.node("T", f"Target\n{target}", shape="box", style="rounded,filled", fillcolor="#eeeeff")
        dot.node("I", f"IP\n{ip}", shape="box", style="rounded,filled", fillcolor="#eeffee")
        dot.edge("T", "I", label="resolves")

        # Porte
        if ports:
            dot.node("P", f"Porte aperte\n{', '.join(map(str, ports))}", shape="box", style="rounded,filled", fillcolor="#ffeeee")
            dot.edge("I", "P", label="services")

        # Subdomains
        for idx, s in enumerate(subs[:40], 1):
            sid = f"S{idx}"
            label = f"{s.get('subdomain')}\\n{s.get('ip')}"
            dot.node(sid, label, shape="ellipse")
            dot.edge("T", sid, label="sub")

        # render
        tmp_path = png_path[:-4]  # senza .png
        dot.render(tmp_path, cleanup=True)
        return png_path
    except Exception as e:
        warn(f"Impossibile generare recon graph: {e}")
        return None

# ─────────────────────────────────────────────────────────────
# Snapshot sito (opzionale). Se Selenium/Chromium non disponibili, salta.

def take_website_screenshot(domain_or_ip: str, out_dir: str) -> Optional[str]:
    """
    Tenta di fare screenshot http(s)://target
    Richiede selenium + un browser installato (+ webdriver).
    Se qualcosa manca, salta senza errori.
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        os.makedirs(out_dir, exist_ok=True)

        target = domain_or_ip
        url_candidates = [
            f"https://{target}",
            f"http://{target}",
            f"https://www.{target}",
            f"http://www.{target}",
        ]

        chrome_opts = Options()
        chrome_opts.add_argument("--headless=new")
        chrome_opts.add_argument("--no-sandbox")
        chrome_opts.add_argument("--disable-gpu")
        chrome_opts.add_argument("--window-size=1366,768")

        try:
            driver = webdriver.Chrome(options=chrome_opts)
        except Exception:
            try:
                driver = webdriver.Edge(options=chrome_opts)
            except Exception:
                warn("Nessun webdriver compatibile trovato per lo screenshot — salto.")
                return None

        path = os.path.join(out_dir, f"snap_{target.replace('.', '_')}_{int(time.time())}.png")
        ok = False
        for url in url_candidates:
            try:
                driver.get(url)
                time.sleep(2.2)
                driver.save_screenshot(path)
                ok = True
                break
            except Exception:
                continue
        driver.quit()
        return path if ok else None
    except Exception as e:
        warn(f"Screenshot non eseguito: {e}")
        return None

# ─────────────────────────────────────────────────────────────
# Security Score Card + Suggestions

CRITICAL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

def build_security_scorecard(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Costruisce una scorecard contestuale con pesi e classi di rischio.
    Pesi default: Ports 40%, AbuseIPDB 30%, VirusTotal 20%, DNS 10%
    """
    ports = report.get("open_ports") or []
    abuse = (report.get("abuseipdb") or {}).get("score", None)
    vt = report.get("virustotal")
    vt_eval = None
    if isinstance(vt, dict):
        vt_eval = vt.get("reputation", None)
    dns_exposure = len(report.get("subdomains") or [])

    # Valutazioni testuali + numeriche
    # Porte critiche = conteggio delle note in CRITICAL_PORTS
    crit_list = [p for p in ports if p in CRITICAL_PORTS]
    ports_severity = "Basso"
    if len(crit_list) >= 4 or 445 in ports or 3389 in ports:
        ports_severity = "Alto"
    elif len(crit_list) >= 2:
        ports_severity = "Medio"

    abuse_severity = "N/A"
    if abuse is not None:
        abuse_severity = "Basso"
        if abuse >= 75:
            abuse_severity = "Alto"
        elif abuse >= 40:
            abuse_severity = "Medio"

    vt_severity = "N/A"
    try:
        if vt_eval is not None and vt_eval != "N/A":
            # reputazione VT spesso è un intero (negativo/positivo). Gestione conservativa:
            if isinstance(vt_eval, int) and vt_eval >= 50:
                vt_severity = "Alto"
            elif isinstance(vt_eval, int) and vt_eval >= 10:
                vt_severity = "Medio"
            else:
                vt_severity = "Basso"
        else:
            vt_severity = "Basso"
    except:
        vt_severity = "Basso"

    dns_severity = "Basso" if dns_exposure <= 1 else ("Medio" if dns_exposure <= 3 else "Alto")

    # Score grezzo 0–100 seguendo pesi: 40/30/20/10
    def sev_to_points(sev, maxp):
        return {"Basso": 0.3*maxp, "Medio": 0.6*maxp, "Alto": 1.0*maxp}.get(sev, 0)

    total = 0
    total += sev_to_points(ports_severity, 40)
    total += sev_to_points(abuse_severity, 30)
    total += sev_to_points(vt_severity, 20)
    total += sev_to_points(dns_severity, 10)
    total = int(round(total))

    # Decorazioni
    def sev_icon(s):
        return {"Alto": "🔴", "Medio": "🟡", "Basso": "🟢", "N/A": "⚪"}.get(s, "⚪")

    scorecard = {
        "overall_score": total,
        "factors": [
            {
                "name": "Porte critiche aperte",
                "value": f"{len(crit_list)} ({', '.join(map(str, crit_list))})" if crit_list else "0",
                "weight": "40%",
                "risk": f"{sev_icon(ports_severity)} {ports_severity}"
            },
            {
                "name": "Reputation AbuseIPDB",
                "value": f"{abuse}/100" if abuse is not None else "N/D",
                "weight": "30%",
                "risk": f"{sev_icon(abuse_severity)} {abuse_severity}"
            },
            {
                "name": "VirusTotal",
                "value": f"{vt_eval}" if vt_eval is not None else "N/D",
                "weight": "20%",
                "risk": f"{sev_icon(vt_severity)} {vt_severity}"
            },
            {
                "name": "DNS Exposure",
                "value": f"{dns_exposure} subdomain pubblici",
                "weight": "10%",
                "risk": f"{sev_icon(dns_severity)} {dns_severity}"
            }
        ]
    }
    return scorecard

def generate_suggestions(report: Dict[str, Any]) -> List[str]:
    """
    Suggerimenti rapidi in base a porte esposte e segnali TI.
    """
    ports = set(report.get("open_ports") or [])
    tips = []

    if 21 in ports:
        tips.append("FTP (21) esposto: disabilitare accesso anonimo, forzare FTPS/SFTP o chiudere se non necessario.")
    if 22 in ports:
        tips.append("SSH (22) esposto: usare key-based auth, fail2ban, cambiare porta, limitare per IP.")
    if 80 in ports and 443 not in ports:
        tips.append("HTTP senza HTTPS: abilitare TLS e redirect 80→443.")
    if 445 in ports:
        tips.append("SMB (445) esposto: restringere via firewall/VPN, disabilitare se non necessario.")
    if 3389 in ports:
        tips.append("RDP (3389) esposto: non pubblicare, usare VPN e MFA.")
    if 25 in ports:
        tips.append("SMTP (25) esposto: SPF/DKIM/DMARC corretti e rate limiting.")

    abuse = (report.get("abuseipdb") or {}).get("score", 0)
    if abuse >= 75:
        tips.append("AbuseIPDB score alto: investigare traffico in uscita e possibili compromissioni.")
    vt = report.get("virustotal")
    if isinstance(vt, dict) and str(vt.get("reputation", "")).strip() not in ("", "N/A"):
        tips.append("Reputazione VirusTotal non pulita: verificare indicatori di compromissione.")

    if not tips:
        tips.append("Nessuna criticità evidente: mantenere patching, hardening e monitoraggio periodico.")
    return tips
