# 🧩 ReconAutomator — by Daniel Filiu Mayedo (0xCondor)

**Automated reconnaissance & threat-intelligence toolkit**

---

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Release-v1.0.0-yellow)

---

## 🔎 Descrizione

ReconAutomator è un toolkit in **Python** progettato per automatizzare la fase di **ricognizione** e raccolta di **threat intelligence** per penetration tester ed ethical hacker.
Il tool è pensato per essere **modulare**, **sicuro** (modalità safe by default) e **usabile anche senza API keys**.

> ⚠️ **Solo per test autorizzati.** Usa il tool esclusivamente su sistemi di tua proprietà o con esplicita autorizzazione.

---

## ✨ Funzionalità principali

* Scansione porte TCP con **Nmap** (profili: `safe`, `service`, `vuln`, `udp`)
* Enumerazione di subdomain comuni
* Threat intelligence tramite:

  * **VirusTotal** (reputazione IP) — opzionale
  * **AbuseIPDB** (abuse score) — opzionale
  * **HaveIBeenPwned** — opzionale
* **Security Score Card** (0–100) che combina fattori ponderati per una vista manageriale rapida
* **Recon Graph** (Graphviz) — visualizzazione grafica IP → subdomains → porte
* **Passive Recon**: crt.sh, ipinfo, WHOIS
* **Website Snapshot** (Selenium) — screenshot della homepage (opzionale)
* Export report su console e in **JSON** / **Markdown**
* Storico scansioni (`reports/history.json`) con diff tra esecuzioni

---

## ⚙️ Requisiti

* Python 3.9+
* (opzionale ma consigliato) `nmap` nel PATH
* Per funzioni avanzate:

  * `graphviz` (binario di sistema) → per generare PNG grafici
  * `selenium` + WebDriver (Chromium/Chrome) → per screenshot

---

## 🛠️ Installazione

```bash
git clone https://github.com/0xCondor/recon-automator.git
cd recon-automator

# virtualenv
python3 -m venv venv
source venv/bin/activate   # Windows PowerShell: .\venv\Scripts\Activate.ps1

# dipendenze Python
pip install -r requirements.txt
```

Opzionale (feature grafiche / screenshot):

```bash
# Graphviz (Debian/Ubuntu)
sudo apt update && sudo apt install -y graphviz

# (opzionale) Chromium per screenshot
sudo apt install -y chromium-browser
# e WebDriver compatibile (chromedriver) — installalo secondo la tua distro/versione
```

---

## 🚀 Esempio d'uso (CLI interattiva)

```bash
# interattivo (menu)
python -m recon_automator.interactive
```

Esempi non-interattivi (in arrivo):

```bash
# futuro: python -m recon_automator.main --target example.com --profile safe --export report.json
```

---

## 📁 Output / Cartelle

* `reports/` — report JSON/MD, screenshot, grafici
* `reports/history.json` — cronologia scansioni e diff
* `reports/graphs/` — PNG generati con Graphviz
* `reports/screenshots/` — screenshot dei siti (se eseguiti)

> Nota: `reports/` è ignorata da Git via `.gitignore`. Se vuoi includere un placeholder, usa `reports/.gitkeep`.

---

## 🔒 API Keys (opzionali)

Le API keys sono **opzionali**: il tool funziona anche senza.
Per aggiungere le chiavi:

1. Avvia il tool → `Configura API keys`
2. Inserisci le chiavi per:

   * VirusTotal
   * AbuseIPDB
   * HaveIBeenPwned

Le chiavi vengono salvate in `config.json` (in `.gitignore`) con permessi utente.

---

## 🦯 Modelli di scan (breve)

* **safe** — `-sS -Pn -p <common ports> -T3` (default, conservativo)
* **service** — `-sS -sV --top-ports 200 -T4` (service/version detection)
* **vuln** — `--script=vuln,...` (invasivo — richiede conferma)
* **udp** — `-sU -p 53,67,69,123` (lento e rumoroso — richiede conferma)

---

## 📄 Licenza & Disclaimer

MIT License — uso consentito solo per test autorizzati.
© 2025 Daniel Filiu Mayedo (0xCondor)

---

## 🧑‍💻 Contatti / Author

**Daniel Filiu Mayedo (0xCondor)**
Ethical Hacker · Penetration Tester

* GitHub: [https://github.com/0xCondor](https://github.com/0xCondor)
* LinkedIn: [https://linkedin.com/in/daniel-filiu-mayedo](https://linkedin.com/in/daniel-filiu-mayedo)

---
