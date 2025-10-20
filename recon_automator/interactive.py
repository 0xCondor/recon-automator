# recon_automator/interactive.py
# Interfaccia interattiva completa per Recon Automator
import os
import sys
import time
from datetime import datetime

# importi relativi al package
from .core import run_scan
from .report import (
    print_report,
    export_json,
    export_markdown,
    append_history
)
from .utils import load_config, save_config, info, warn, err

# ─────────────────────────────────────────────────────────────
# Banner personalizzato — modificabile se vuoi
BANNER = r"""
╔════════════════════════════════════════════════════════════════╗
║   █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗║
║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝║
║  ███████║██║   ██║   ██║   ██║   ██║██╔████╔██║███████║   ██║   ║
║  ██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ║
║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║   ██║   ║
║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ║
║                                                                ║
║              AUTOMATOR by Daniel Filiu Mayedo (aka 0xCondor)   ║
╚════════════════════════════════════════════════════════════════╝
"""

DISCLAIMER = """
⚠️  DISCLAIMER ⚠️

Questo tool è fornito esclusivamente per scopi educativi e per test autorizzati.
Non usarlo per attività non autorizzate. L'autore (Daniel Filiu Mayedo - 0xCondor)
e FiliuTech declinano ogni responsabilità per eventuali abusi.

Premi 'y' per confermare che stai operando in modo etico e legale.
"""

REPORT_DIR = "reports"
last_report = None

# ─────────────────────────────────────────────────────────────
def clear_screen():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass

def pause():
    try:
        input("\nPremi INVIO per continuare...")
    except Exception:
        pass

def show_banner_and_disclaimer():
    clear_screen()
    print(BANNER)
    print(DISCLAIMER)
    ans = input("Confermi (y/N)? ").strip().lower()
    if ans != "y":
        print("Operazione annullata. Uscita.")
        sys.exit(0)

def show_menu():
    clear_screen()
    print(BANNER)
    print("Menu principale:")
    print(" 1) Inserisci dominio/IP e avvia scansione")
    print(" 2) Configura API keys (opzionali)")
    print(" 3) Mostra API keys attive")
    print(" 4) Mostra ultimo report")
    print(" 5) Esporta ultimo report (JSON + Markdown)")
    print(" 6) Esci")
    return input("\nSeleziona (1-6): ").strip()

# ─────────────────────────────────────────────────────────────
def configure_apis(api_keys):
    clear_screen()
    print("== Configurazione API Keys (lascia vuoto per non modificare) ==")
    print("Le API sono opzionali: il tool funziona anche senza di esse.\n")
    print(f"VirusTotal: {'✅' if api_keys.get('vt') else '—'}")
    print(f"AbuseIPDB : {'✅' if api_keys.get('abuse') else '—'}")
    print(f"HIBP      : {'✅' if api_keys.get('hibp') else '—'}\n")

    vt = input("VirusTotal API Key: ").strip()
    abuse = input("AbuseIPDB API Key: ").strip()
    hibp = input("HaveIBeenPwned API Key: ").strip()

    if vt:
        api_keys["vt"] = vt
    if abuse:
        api_keys["abuse"] = abuse
    if hibp:
        api_keys["hibp"] = hibp

    save_config(api_keys)
    info("API keys salvate localmente (file config.json).")
    pause()
    return api_keys

def show_api_status(api_keys):
    clear_screen()
    print("== API Keys attualmente configurate ==")
    print(f"VirusTotal: {'Configurata' if api_keys.get('vt') else 'Non configurata'}")
    print(f"AbuseIPDB : {'Configurata' if api_keys.get('abuse') else 'Non configurata'}")
    print(f"HIBP      : {'Configurata' if api_keys.get('hibp') else 'Non configurata'}")
    pause()

# ─────────────────────────────────────────────────────────────
def choose_nmap_profile():
    """
    Chiede all'utente quale profilo nmap utilizzare e gestisce il warning per profili intrusivi.
    """
    print("\nScegli profilo nmap:")
    print(" 1) safe    (default) — rapido e conservativo")
    print(" 2) service — detect service/version (più rumoroso)")
    print(" 3) vuln    — usa NSE vuln scripts (invasivo, richiede conferma)")
    print(" 4) udp     — controllo UDP (lento, richiede conferma)")
    choice = input("Seleziona (1-4, INVIO per default=1): ").strip()
    mapping = {"1": "safe", "2": "service", "3": "vuln", "4": "udp"}
    profile = mapping.get(choice, "safe")
    if profile in ("vuln", "udp"):
        ans = input(f"ATTENZIONE: il profilo '{profile}' può essere intrusivo. Confermi (y/N)? ").strip().lower()
        if ans != "y":
            print("Profilo invasivo rifiutato — uso 'safe'.")
            return "safe"
    return profile

def run_scan_interactive(api_keys):
    """
    Esegue la scansione interattiva con barra di progresso e profili Nmap.
    """
    import sys
    import itertools

    global last_report
    clear_screen()
    print("== Avvia scansione ==")
    target = input("Inserisci dominio o IP: ").strip()
    if not target:
        warn("Target vuoto — annullo.")
        pause()
        return

    profile = choose_nmap_profile()
    info(f"Avvio scansione per {target} con profilo '{profile}' (le API sono opzionali).")

    # ─────────────────────────────────────────────
    # Barra di caricamento simulata durante la scansione
    def loading_animation(message: str, duration: int):
        spinner = itertools.cycle(["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"])
        start = time.time()
        while time.time() - start < duration:
            sys.stdout.write(f"\r{next(spinner)} {message}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r✓ Scansione completata. Elaborazione risultati...\n")

    # Durata simulata in base al profilo
    duration_map = {"safe": 3, "service": 6, "vuln": 10, "udp": 8}
    duration = duration_map.get(profile, 3)

    # Avvia animazione in un thread separato
    import threading
    loader_thread = threading.Thread(target=loading_animation, args=("Scanning in corso...", duration))
    loader_thread.start()

    # Esegui realmente la scansione
    report = run_scan(target, api_keys, nmap_profile=profile)

    # Attendi la fine dell'animazione
    loader_thread.join()
    # ─────────────────────────────────────────────

    if not report:
        err("Errore: impossibile risolvere il target o eseguire la scansione.")
        pause()
        return

    last_report = report
    print_report(report)

    # salva history (append)
    try:
        summary = append_history(report)
        info(f"History aggiornata (target: {summary.get('target')}, risk_score: {summary.get('risk_score')})")
    except Exception as e:
        warn(f"Non è stato possibile aggiornare la history: {e}")

    pause()


    # run_scan (core) gestisce resolve_target, nmap_profile, api calls e risk_score
    report = run_scan(target, api_keys, nmap_profile=profile)
    if not report:
        err("Errore: impossibile risolvere il target o eseguire la scansione.")
        pause()
        return

    last_report = report
    print_report(report)

    # salva history (append)
    try:
        summary = append_history(report)
        info(f"History aggiornata (target: {summary.get('target')}, risk_score: {summary.get('risk_score')})")
    except Exception as e:
        warn(f"Non è stato possibile aggiornare la history: {e}")

    pause()

def export_last_report_interactive():
    """
    Esporta l'ultimo report in JSON e Markdown nella cartella reports/.
    I file hanno nome automatico con timestamp.
    """
    global last_report
    if not last_report:
        warn("Nessun report disponibile da esportare.")
        pause()
        return

    os.makedirs(REPORT_DIR, exist_ok=True)

    target_name = last_report.get("target", "unknown").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = os.path.join(REPORT_DIR, f"report_{target_name}_{timestamp}.json")
    md_filename = os.path.join(REPORT_DIR, f"report_{target_name}_{timestamp}.md")

    try:
        export_json(last_report, json_filename)
        export_markdown(last_report, md_filename)
        info(f"Report salvati in:\n - {json_filename}\n - {md_filename}")
    except Exception as e:
        err(f"Errore durante export: {e}")

    pause()

# ─────────────────────────────────────────────────────────────
def main_loop():
    api_keys = load_config() or {}
    show_banner_and_disclaimer()

    while True:
        choice = show_menu()
        if choice == "1":
            run_scan_interactive(api_keys)
        elif choice == "2":
            api_keys = configure_apis(api_keys)
        elif choice == "3":
            show_api_status(api_keys)
        elif choice == "4":
            clear_screen()
            print("== Ultimo report ==")
            if last_report:
                print_report(last_report)
            else:
                print("Nessun report ancora eseguito.")
            pause()
        elif choice == "5":
            export_last_report_interactive()
        elif choice == "6":
            info("Uscita. Alla prossima, 0xCondor 👋")
            break
        else:
            warn("Scelta non valida, riprova.")
            time.sleep(0.6)

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nInterrotto da utente. Uscita.")
        sys.exit(0)
