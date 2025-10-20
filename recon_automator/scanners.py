# recon_automator/scanners.py
import socket
import subprocess
import re
import requests
from typing import List, Optional

def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

def parse_nmap_grepable(output: str) -> List[int]:
    open_ports = []
    for line in (output or "").splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            parts = line.split("Ports:")[-1]
            for p in parts.split(','):
                m = re.match(r"(\d+)/open/tcp", p.strip())
                if m:
                    try:
                        open_ports.append(int(m.group(1)))
                    except:
                        pass
    return sorted(set(open_ports))

def run_nmap_profile(ip: str, profile: str = "safe", timeout: int = 120) -> Optional[List[int]]:
    """
    Esegue nmap con uno dei profili predefiniti e ritorna lista di porte aperte.
    Restituisce:
      - list[int] : porte aperte
      - []        : nessuna porta aperta trovata
      - None      : nmap non installato / errore FileNotFound
    Profili: safe, service, vuln, udp
    """
    profiles = {
        "safe": ["-sS", "-Pn", "-p", "21,22,25,53,80,110,139,143,443,445,8080", "--open", "-T3", "--max-retries", "2", "--host-timeout", "30s", "-oG", "-"],
        "service": ["-sS", "-sV", "-Pn", "--top-ports", "200", "-T4", "--max-retries", "3", "--host-timeout", "2m", "-oG", "-"],
        "vuln": ["-sS", "-sV", "-Pn", "--script=vuln,http-enum,ssl-enum-ciphers", "-T4", "--max-retries", "3", "--host-timeout", "3m", "-oG", "-"],
        "udp": ["-sU", "-Pn", "-p", "53,67,69,123", "--open", "-T3", "--max-retries", "2", "--host-timeout", "2m", "-oG", "-"]
    }

    args = profiles.get(profile, profiles["safe"]) + [ip]
    cmd = ["nmap"] + args
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0 and (res.stdout is None or res.stdout.strip() == ""):
            # possibile errore o nmap non presente
            return parse_nmap_grepable(res.stdout)
        return parse_nmap_grepable(res.stdout)
    except FileNotFoundError:
        # nmap non installato
        return None
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

def enumerate_subdomains(domain: str, common_list=None):
    if common_list is None:
        common_list = ["www", "mail", "ftp", "admin", "dev", "test", "api"]
    found = []
    for s in common_list:
        host = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append({"subdomain": host, "ip": ip})
        except Exception:
            continue
    return found

def virustotal_check(ip: str, vt_key: str):
    if not vt_key:
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": vt_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            rep = data.get("data", {}).get("attributes", {}).get("reputation", "N/A")
            return {"reputation": rep}
    except:
        return None
    return None

def abuseipdb_check(ip: str, abuse_key: str):
    if not abuse_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": abuse_key}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            return {"score": score}
    except:
        return None
    return None
