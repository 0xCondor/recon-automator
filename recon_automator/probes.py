# recon_automator/probes.py
# Async HTTP probing + light tech fingerprinting
import asyncio
import re
from typing import List, Dict, Any, Optional

# Probing uses httpx + BeautifulSoup if available; falls back gracefully
try:
    import httpx
    from bs4 import BeautifulSoup
    HAS_HTTPX = True
except Exception:
    HAS_HTTPX = False

# Simple heuristics for tech fingerprinting (extend later)
TECH_PATTERNS = {
    "wordpress": [r"wp-content", r"WordPress"],
    "nginx": [r"nginx"],
    "apache": [r"Apache"],
    "cloudflare": [r"cloudflare"],
    "express": [r"Express"],
    "react": [r"data-reactroot", r"<div id=\"root\">"],
    "php": [r"\.php"],
}

DEFAULT_TIMEOUT = 6.0

def _fingerprint_from_headers_and_body(headers: Dict[str, Any], body: str) -> List[str]:
    """Semplice fingerprinting: cerca pattern nelle headers / body"""
    found = set()
    hs = " ".join([f"{k}:{v}" for k, v in (headers or {}).items()]).lower()
    lower_body = (body or "").lower()
    for tech, pats in TECH_PATTERNS.items():
        for p in pats:
            try:
                if re.search(p.lower(), hs) or re.search(p.lower(), lower_body):
                    found.add(tech)
            except re.error:
                continue
    return sorted(found)

async def async_probe_url(client: "httpx.AsyncClient", url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Prova a fare GET su `url`, ritorna: url, status, title, headers (selected), server, tech list, error(optional)
    """
    result = {"url": url, "status": None, "title": None, "server": None, "headers": {}, "tech": [], "error": None}
    if not HAS_HTTPX:
        result["error"] = "httpx/bs4 non installati"
        return result

    try:
        r = await client.get(url, follow_redirects=True, timeout=timeout)
        result["status"] = r.status_code
        # selected headers
        headers = {}
        for h in ("server", "x-powered-by", "content-type", "via"):
            if r.headers.get(h):
                headers[h] = r.headers.get(h)
        result["headers"] = headers
        result["server"] = r.headers.get("server")
        # title extraction
        ctype = r.headers.get("content-type", "")
        text = ""
        if "html" in ctype and r.text:
            text = r.text
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                t = soup.title
                if t and t.string:
                    result["title"] = t.string.strip()
            except Exception:
                pass
        # fingerprint
        result["tech"] = _fingerprint_from_headers_and_body(r.headers, text)
    except httpx.RequestError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result

async def _probe_candidates_async(candidates: List[str], concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    Prova una lista di URL (completa: 'https://a.example' o 'http://...').
    """
    if not HAS_HTTPX:
        return [{"url": u, "error": "httpx/bs4 not installed"} for u in candidates]

    results = []
    timeout = DEFAULT_TIMEOUT
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(http2=True, verify=True) as client:
        async def _bounded_probe(u):
            async with sem:
                return await async_probe_url(client, u, timeout=timeout)

        tasks = [asyncio.create_task(_bounded_probe(u)) for u in candidates]
        for coro in asyncio.as_completed(tasks):
            try:
                r = await coro
            except Exception as e:
                r = {"url": "unknown", "error": str(e)}
            results.append(r)
    return results

def build_url_candidates_for_domain(domain: str) -> List[str]:
    """
    Genera candidati URL da provare per un host/domain.
    """
    domain = domain.strip()
    hosts = [
        domain,
        f"www.{domain}",
    ]
    candidates = []
    for h in hosts:
        candidates.append(f"https://{h}")
        candidates.append(f"http://{h}")
    return candidates

def probe_subdomains_sync(subdomains: List[dict], concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    API sync: riceve lista di subdomains [{"subdomain": "a.example", "ip": "1.2.3.4"}, ...]
    Ritorna lista con ogni subdomain arricchito con chiave 'probe'.
    """
    if not HAS_HTTPX:
        return [{"subdomain": s.get("subdomain"), "ip": s.get("ip"), "probe": {"error": "httpx/bs4 not installed"}} for s in subdomains]

    # genera URL da provare (https/http) per ogni subdomain
    candidates = []
    for s in subdomains:
        host = s.get("subdomain")
        urls = build_url_candidates_for_domain(host)
        candidates.extend(urls)

    results = asyncio.run(_probe_candidates_async(candidates, concurrency=concurrency))

    # aggregate: pick first successful per host
    by_host = {}
    for r in results:
        u = r.get("url") or ""
        try:
            host = re.sub(r"^https?://", "", u).split("/")[0]
        except Exception:
            host = u
        if not host:
            continue
        if host not in by_host:
            by_host[host] = r
        else:
            existing = by_host[host]
            if (existing.get("status") is None or existing.get("error")) and (r.get("status") is not None and not r.get("error")):
                by_host[host] = r

    out = []
    for s in subdomains:
        host = s.get("subdomain")
        res = by_host.get(host, None)
        rec = {
            "subdomain": host,
            "ip": s.get("ip"),
            "probe": res
        }
        out.append(rec)
    return out

def probe_host_sync(host_or_domain: str, concurrency: int = 6) -> List[Dict[str, Any]]:
    """
    Prova il dominio principale e ritorna i risultati (https/http).
    """
    urls = build_url_candidates_for_domain(host_or_domain)
    if not HAS_HTTPX:
        return [{"url": u, "error": "httpx/bs4 not installed"} for u in urls]
    results = asyncio.run(_probe_candidates_async(urls, concurrency=concurrency))
    return results
