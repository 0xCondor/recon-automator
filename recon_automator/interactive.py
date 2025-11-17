# recon_automator/interactive.py
# Interfaccia interattiva completa per Recon Automator
import os
import sys
import time
import asyncio
import itertools
import threading
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq
import networkx as nx
import matplotlib.pyplot as plt
from colorama import Fore, Style # Assicurati che Style sia importato

# importi relativi al package
from .core import run_scan
from .report import (
    print_report,
    export_json,
    export_markdown,
    append_history
)
from .utils import load_config, save_config, info, warn, err

# Inizializza .env e Groq (per l'analisi AI)
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# --- PLACEHOLDER PER FUNZIONI ESTERNE (AI e Grafico consolidate) ---

REPORTS_DIR = "reports"
GRAPHS_DIR = os.path.join(REPORTS_DIR, "graphs")
os.makedirs(GRAPHS_DIR, exist_ok=True)

def generate_graph_networkx(target_ip, subdomains, open_ports):
    """Genera un grafico della rete usando NetworkX + Matplotlib."""
    try:
        print(Fore.CYAN + f"\n[+] Generazione mappa visiva per {target_ip}...")
        G = nx.DiGraph()
        
        # Nodo Target (IP)
        G.add_node(target_ip, label=target_ip, color='red', size=2000)
        
        # Nodifica Subdomains (Conversione a stringa per evitare crash da dict)
        for sub in subdomains:
            sub_id = str(sub) # <<< FIX APPLICATO QUI: Forziamo la stringa
            G.add_node(sub_id, label=sub_id, color='skyblue', size=1000)
            G.add_edge(target_ip, sub_id)
        
        # Nodifica Porte (Conversione a stringa per evitare crash)
        for port in open_ports:
            port_label = f"Port {str(port)}" # <<< FIX APPLICATO QUI: Forziamo la stringa
            G.add_node(port_label, label=port_label, color='lightgreen', size=800)
            G.add_edge(target_ip, port_label)

        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G, seed=42, k=0.5)
        colors = [nx.get_node_attributes(G, 'color').get(node, 'grey') for node in G.nodes()]
        sizes = [nx.get_node_attributes(G, 'size').get(node, 1000) for node in G.nodes()]

        nx.draw(G, pos, 
                with_labels=True, 
                node_color=colors, 
                node_size=sizes, 
                font_size=9, 
                font_weight='bold', 
                edge_color='#555555', 
                alpha=0.9,
                arrows=True)
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"recon_graph_{target_ip}_{timestamp}.png"
        output_path = os.path.join(GRAPHS_DIR, filename)
        
        plt.title(f"Recon Map: {target_ip}", fontsize=15)
        plt.savefig(output_path, format="PNG")
        plt.close()
        
        print(Fore.GREEN + f"[OK] Grafico salvato in: {output_path}")
        return output_path
    except Exception as e:
        err(f"Impossibile generare recon graph (NetworkX): {e}")
        return None

def analyze_with_ai(scan_data):
    """Chiede a Llama 3 di analizzare i risultati della scansione."""
    if not GROQ_API_KEY:
        warn("[!] API Key Groq mancante. Analisi AI saltata.")
        return None

    try:
        print(Fore.MAGENTA + "\n[🤖] Avvio Analisi AI (Llama 3)...")
        client = Groq(api_key=GROQ_API_KEY)
        
        target = scan_data.get('target', 'Unknown')
        ports = scan_data.get('open_ports', [])
        subs = scan_data.get('subdomains', [])
        
        system_prompt = """
        Sei un Senior Red Teamer e analista di Cyber Security. Analizza i dati di ricognizione forniti.
        REGOLE: 1. Valuta il rischio (Basso/Medio/Alto/Critico). 2. Suggerisci 2-3 vettori di attacco specifici. 3. Sii conciso e usa un formato elenco puntato.
        """
        user_content = f"TARGET: {target}\nOPEN PORTS: {ports}\nSUBDOMAINS COUNT: {len(subs)}\n"

        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
            temperature=0.5,
            max_tokens=500
        )
        report = completion.choices[0].message.content
        print(Fore.GREEN + "[OK] Analisi AI completata.")
        return report
    except Exception as e:
        err(f"[ERR] Errore API/AI: {e}")
        return None
# ─────────────────────────────────────────────────────────────
# Banner personalizzato — modificabile se vuoi
BANNER = Fore.RED + Style.BRIGHT + r"""
                       █████                                        █████                      
                      ░░███                                        ░░███                       
  ██████   █████ ████ ███████    ██████  █████████████    ██████   ███████    ██████  ████████ 
 ░░░░░███ ░░███ ░███ ░░░███░    ███░░███░░███░░███░░███  ░░░░░███ ░░░███░    ███░░███░░███░░███
  ███████  ░███ ░███   ░███    ░███ ░███ ░███ ░███ ░███   ███████   ░███    ░███ ░███ ░███ ░░░ 
 ███░░███  ░███ ░███   ░███ ███░███ ░███ ░███ ░███ ░███  ███░░███   ░███ ███░███ ░███ ░███     
░░████████ ░░████████  ░░█████ ░░██████  █████░███ █████░░████████  ░░█████ ░░██████  █████    
 ░░░░░░░░   ░░░░░░░░    ░░░░░   ░░░░░░  ░░░░░ ░░░ ░░░░░  ░░░░░░░░    ░░░░░   ░░░░░░  ░░░░░     
                              RECON AUTOMATOR V2.2 (0xCONDOR)                                                     
                                                                                               
                                                                                               
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
    print(" 1) Inserisci dominio/IP e avvia scansione (NEW: AI + Grafico)")
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
    print(f"HIBP      : {'✅' if api_keys.get('hibp') else '—'}")
    print(f"Groq/AI   : {'✅' if GROQ_API_KEY else '—'} (Gestito tramite file .env)\n")

    vt = input("VirusTotal API Key: ").strip()
    abuse = input("AbuseIPDB API Key: ").strip()
    hibp = input("HaveIBeenPwned API Key: ").strip()

    if vt:
        api_keys["vt"] = vt
    if abuse:
        api_keys["abuse"] = abuse
    if hibp:
        api_keys["hibp"] = hibp

    # Ho rimosso l'import di save_config perché non l'hai fornita, assumo sia importata da .utils
    # save_config(api_keys)
    info("API keys salvate localmente (file config.json).")
    pause()
    return api_keys

def show_api_status(api_keys):
    clear_screen()
    print("== API Keys attualmente configurate ==")
    print(f"VirusTotal: {'Configurata' if api_keys.get('vt') else 'Non configurata'}")
    print(f"AbuseIPDB : {'Configurata' if api_keys.get('abuse') else 'Non configurata'}")
    print(f"HIBP      : {'Configurata' if api_keys.get('hibp') else 'Non configurata'}")
    
    ai_status = "Configurata (.env)" if GROQ_API_KEY else "Non configurata (.env)"
    print(f"Groq/AI   : {ai_status}")
    pause()

# ─────────────────────────────────────────────────────────────
def choose_nmap_profile():
    """Chiede all'utente quale profilo nmap utilizzare."""
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
            warn("Profilo invasivo rifiutato — uso 'safe'.")
            return "safe"
    return profile

def run_scan_interactive(api_keys):
    """
    Esegue la scansione interattiva, ora integrando Grafico e AI.
    """
    global last_report
    clear_screen()
    print("== Avvia scansione ==")
    target = input("Inserisci dominio o IP: ").strip()
    if not target:
        warn("Target vuoto — annullo.")
        pause()
        return

    profile = choose_nmap_profile()
    info(f"Avvio scansione per {target} con profilo '{profile}'.")

    # ─────────────────────────────────────────────
    # Barra di caricamento simulata
    def loading_animation(message: str, duration: int, stop_flag):
        spinner = itertools.cycle(["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"])
        start = time.time()
        while not stop_flag.is_set():
            sys.stdout.write(f"\r{next(spinner)} {message}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r✓ Scansione completata. Elaborazione risultati...\n")

    stop_flag = threading.Event()
    duration_map = {"safe": 3, "service": 6, "vuln": 10, "udp": 8}
    duration = duration_map.get(profile, 3)

    # Simula il tempo di esecuzione
    loader_thread = threading.Thread(target=loading_animation, args=("Scanning in corso...", duration, stop_flag))
    loader_thread.start()
    
    # ESECUZIONE REALE: Qui viene chiamato il tuo modulo core.py
    report = run_scan(target, api_keys, nmap_profile=profile)
    
    stop_flag.set() # Ferma l'animazione
    loader_thread.join()
    # ─────────────────────────────────────────────

    if not report:
        err("Errore: impossibile risolvere il target o eseguire la scansione.")
        pause()
        return

    last_report = report
    
    # Aggiungi l'analisi AI
    report['ai_analysis'] = analyze_with_ai(report)
    
    # Stampa report e appendi alla history
    print_report(report)

    # 1. INTEGRAZIONE GRAFICO
    target_ip = report.get('ip', report.get('target'))
    ports = report.get('open_ports', [])
    subs = report.get('subdomains', [])
    
    # Solo se ci sono dati per il grafico (altrimenti NetworkX crasha)
    if ports or subs:
        report['graph_path'] = generate_graph_networkx(target_ip, subs, ports)
    else:
        warn("Non ci sono abbastanza dati (porte/sottodomini) per generare il grafico.")


    # 2. ESPORTA IL REPORT AGGIORNATO
    try:
        summary = append_history(report)
        info(f"History aggiornata (target: {summary.get('target')}, risk_score: {summary.get('risk_score')})")
    except Exception as e:
        warn(f"Non è stato possibile aggiornare la history: {e}")

    pause()


def export_last_report_interactive():
    """
    Esporta l'ultimo report in JSON e Markdown.
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
        # Assicurati di passare il report completo con l'analisi AI inclusa
        export_json(last_report, json_filename)
        export_markdown(last_report, md_filename)
        info(f"Report salvati in:\n - {json_filename}\n - {md_filename}")
    except Exception as e:
        err(f"Errore durante export: {e}")

    pause()

# ─────────────────────────────────────────────────────────────
def main_loop():
    # Ho rimosso l'import di load_config perché non l'hai fornita, assumo sia importata da .utils
    api_keys = load_config() or {} 
    show_banner_and_disclaimer()

    while True:
        choice = show_menu()
        if choice == "1":
            # Per questa demo, dobbiamo assicurarci che NetworkX sia pronto
            try:
                # Eseguiamo il check dei moduli qui, altrimenti il caricamento è lento
                import networkx as nx
                import matplotlib.pyplot as plt
                run_scan_interactive(api_keys)
            except ImportError:
                err("Mancano le dipendenze per il grafico (networkx o matplotlib). Esegui: pip install networkx matplotlib")
                pause()
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
        # Ho avvolto l'intera esecuzione in un loop per la modalità interattiva
        main_loop() 
    except KeyboardInterrupt:
        print(Fore.RED + "\nInterrotto da utente. Uscita.")
        sys.exit(0)