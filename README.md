# ReconAutomator — by OXCondor

Tool di ricognizione e threat-intel per penetration tester (solo test autorizzati).

## Funzionalità
- Scansione porte TCP comuni (Nmap)
- Enumerazione subdomain comuni
- Threat intel: VirusTotal (reputation), AbuseIPDB (abuse score)
- Report su console ed export JSON

## Requisiti
- Python 3.9+
- Nmap installato nel PATH (opzionale ma consigliato)

## Installazione
```bash
python -m venv venv
source venv/bin/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

### ✨ Feature avanzate
- **Security Score Card** (0–100) con fattori ponderati: porte critiche (40%), AbuseIPDB (30%), VirusTotal (20%), DNS Exposure (10%).
- **Recon Graph** (PNG) — mappa IP → Subdomains → Ports (Graphviz). *Opzionale, auto-salta se non installato.*
- **Passive Recon**: crt.sh (subdomains), IPInfo (ASN/geo), WHOIS (registrar/dates).
- **Website Snapshot** (Selenium) — PNG della homepage se raggiungibile. *Opzionale, auto-salta se non presente WebDriver.*
- **Suggestions** — remediation mirate in base ai segnali (porte SMB/RDP, HTTP senza TLS, reputation alta, ecc.).
