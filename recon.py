#!/usr/bin/env python3
import os
import sys
import json
import time
import argparse
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from dotenv import load_dotenv
from colorama import init, Fore, Style
from groq import Groq

# Inizializzazione Ambiente e Caricamento .env
init(autoreset=True)
load_dotenv() 

# --- CONFIGURAZIONE GLOBALE ---
REPORTS_DIR = "reports"
GRAPHS_DIR = os.path.join(REPORTS_DIR, "graphs")
os.makedirs(GRAPHS_DIR, exist_ok=True)

# NUOVO BANNER ELEGANTE
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

# --- MODULO 1: IL MOTORE GRAFICO (NetworkX) ---
def generate_graph_networkx(target_ip, subdomains, open_ports):
    """Genera un grafico della rete usando solo Python (NetworkX)"""
    print(Fore.CYAN + f"\n[+] Generazione mappa visiva per {target_ip}...")
    
    G = nx.DiGraph()
    G.add_node(target_ip, label=target_ip, color='red', size=2000)
    
    for sub in subdomains:
        sub_id = str(sub) # Assicura tipo stringa (hashable)
        G.add_node(sub_id, label=sub_id, color='skyblue', size=1000)
        G.add_edge(target_ip, sub_id)
        
    for port in open_ports:
        port_label = f"Port {str(port)}"
        G.add_node(port_label, label=port_label, color='lightgreen', size=800)
        G.add_edge(target_ip, port_label)

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=42, k=0.5) 
    node_colors = [nx.get_node_attributes(G, 'color').get(node, 'grey') for node in G.nodes()]
    node_sizes = [nx.get_node_attributes(G, 'size').get(node, 1000) for node in G.nodes()]

    nx.draw(G, pos, 
            with_labels=True, 
            node_color=node_colors, 
            node_size=node_sizes, 
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

# --- MODULO 2: L'INTELLIGENZA ARTIFICIALE (Groq/Llama 3) ---
# Accetta la chiave API come parametro
def analyze_with_ai(scan_data, groq_api_key):
    """Chiede a Llama 3 di analizzare i risultati della scansione"""
    if not groq_api_key:
        print(Fore.YELLOW + "[!] API Key Groq non trovata. Analisi AI saltata.")
        return "Analisi AI non eseguita: API Key mancante."

    print(Fore.MAGENTA + "\n[🤖] Avvio Analisi AI (Cyber Security Analyst)...")
    
    client = Groq(api_key=groq_api_key) 
    
    ports = scan_data.get('ports', [])
    subs = scan_data.get('subdomains', [])
    
    # Prompt Ingegnerizzato per Pentesting
    system_prompt = """
    Sei un Senior Red Teamer. Analizza i dati di ricognizione.
    Output richiesto (Markdown): 1. 🛡️ Valutazione Rischio (Basso/Medio/Alto). 2. 🔍 Vettori di Attacco (2-3 tecniche specifiche). 3. 📝 Prossimi Step (Cosa fare ora). Sii conciso.
    """
    
    user_content = f"TARGET: {scan_data['target']}\nOPEN PORTS: {ports}\nSUBDOMAINS COUNT: {len(subs)}\n"
    
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
            temperature=0.6,
            max_tokens=600
        )
        report = completion.choices[0].message.content
        print(Fore.GREEN + "[OK] Analisi AI completata.")
        return report
    except Exception as e:
        print(Fore.RED + f"[ERR] Errore AI: {e}")
        return "Errore durante l'analisi AI."

# --- MODULO 3: MOCK SCANNER (Simulatore) ---
def run_scan_simulation(target):
    """Esegue una scansione simulata per testare i moduli Grafico e AI."""
    print(Fore.YELLOW + f"[*] Scansione Target: {target}")
    
    # FIX ERROR: Usiamo Style.DIM
    print(Style.DIM + "    -> Risoluzione DNS...") 
    time.sleep(1)
    print(Style.DIM + "    -> Port Scanning (Top 1000)...")
    time.sleep(2) 
    print(Style.DIM + "    -> Subdomain Enumeration...")
    time.sleep(1)
    
    # Dati generati per testare i moduli
    return {
        "target": target,
        "ip": "192.168.1.105",
        "ports": [80, 443, 22, 3306, 8080], 
        "subdomains": [f"www.{target}", f"api.{target}", f"dev.{target}", f"mail.{target}"]
    }

# --- MAIN CONTROLLER ---
def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Automated Recon Tool")
    parser.add_argument("-t", "--target", help="Target domain (es. google.com)", required=True)
    # NUOVO ARGOMENTO PER LA CHIAVE API GROQ
    parser.add_argument("--groq-key", help="Chiave API Groq (opzionale). Sovrascrive il file .env.", required=False) 
    
    args = parser.parse_args()
    target = args.target

    # LOGICA PRIORITÀ CHIAVE: 1. CLI > 2. Ambiente (.env)
    groq_key_to_use = args.groq_key or os.getenv("GROQ_API_KEY")

    # 1. ESEGUI SCANSIONE (Simulata)
    scan_data = run_scan_simulation(target)
    
    print(Fore.WHITE + "\n--- RISULTATI SCANSIONE ---")
    print(f"Target: {scan_data['target']}")
    print(f"Porte Aperte: {scan_data['ports']}")
    
    # 2. ANALISI AI (Passiamo la chiave API)
    ai_report = analyze_with_ai(scan_data, groq_key_to_use)
    
    # 3. GENERA GRAFICO
    generate_graph_networkx(scan_data['target'], scan_data['subdomains'], scan_data['ports'])
    
    # 4. STAMPA REPORT AI
    if ai_report:
        print(Fore.CYAN + "\n" + "="*40)
        print(Fore.CYAN + " REPORT AI (Llama 3) ")
        print(Fore.CYAN + "="*40 + Style.RESET_ALL)
        print(ai_report)
        
        # Salvataggio Report
        report_file = os.path.join(REPORTS_DIR, f"ai_report_{target}.md")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"# AI Recon Report for {target}\n\n")
            f.write(f"### Dati Rilevati:\n{json.dumps(scan_data, indent=2)}\n\n")
            f.write(f"### Analisi AI:\n{ai_report}")

        # FIX ERRORE: Usiamo Style.DIM
        print(Style.DIM + f"\n[i] Report AI salvato in: {report_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Uscita forzata.")
      
#!/usr/bin/env python3
import os
import sys
import json
import time
import argparse
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from dotenv import load_dotenv
from colorama import init, Fore, Style
from groq import Groq

# Inizializzazione Ambiente
init(autoreset=True)
load_dotenv() # Carica la chiave API Groq dal file .env

# --- CONFIGURAZIONE GLOBALE ---
REPORTS_DIR = "reports"
GRAPHS_DIR = os.path.join(REPORTS_DIR, "graphs")
os.makedirs(GRAPHS_DIR, exist_ok=True)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# --- MODULO 1: IL MOTORE GRAFICO (NetworkX) ---
def generate_graph_networkx(target_ip, subdomains, open_ports):
    """Genera un grafico della rete usando solo Python (NetworkX)"""
    print(Fore.CYAN + f"\n[+] Generazione mappa visiva per {target_ip}...")
    
    G = nx.DiGraph()
    G.add_node(target_ip, label=target_ip, color='red', size=2000)
    
    for sub in subdomains:
        G.add_node(sub, label=sub, color='skyblue', size=1000)
        G.add_edge(target_ip, sub)
        
    for port in open_ports:
        port_label = f"Port {port}"
        G.add_node(port_label, label=port_label, color='lightgreen', size=800)
        G.add_edge(target_ip, port_label)

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=42, k=0.5) 
    node_colors = [nx.get_node_attributes(G, 'color').get(node, 'grey') for node in G.nodes()]
    node_sizes = [nx.get_node_attributes(G, 'size').get(node, 1000) for node in G.nodes()]

    nx.draw(G, pos, 
            with_labels=True, 
            node_color=node_colors, 
            node_size=node_sizes, 
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

# --- MODULO 2: L'INTELLIGENZA ARTIFICIALE (Groq/Llama 3) ---
def analyze_with_ai(scan_data):
    """Chiede a Llama 3 di analizzare i risultati della scansione"""
    if not GROQ_API_KEY:
        print(Fore.YELLOW + "[!] API Key Groq non trovata. Analisi AI saltata.")
        return "Analisi AI non eseguita: API Key mancante."

    print(Fore.MAGENTA + "\n[🤖] Avvio Analisi AI (Cyber Security Analyst)...")
    
    client = Groq(api_key=GROQ_API_KEY)
    
    ports = scan_data.get('ports', [])
    subs = scan_data.get('subdomains', [])
    
    # Prompt Ingegnerizzato per Pentesting
    system_prompt = """
    Sei un Senior Red Teamer. Analizza i dati di ricognizione.
    Output richiesto (Markdown): 1. 🛡️ Valutazione Rischio (Basso/Medio/Alto). 2. 🔍 Vettori di Attacco (2-3 tecniche specifiche). 3. 📝 Prossimi Step (Cosa fare ora). Sii conciso.
    """
    
    user_content = f"TARGET: {scan_data['target']}\nOPEN PORTS: {ports}\nSUBDOMAINS COUNT: {len(subs)}\n"
    
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
            temperature=0.6,
            max_tokens=600
        )
        report = completion.choices[0].message.content
        print(Fore.GREEN + "[OK] Analisi AI completata.")
        return report
    except Exception as e:
        print(Fore.RED + f"[ERR] Errore AI: {e}")
        return "Errore durante l'analisi AI."

# --- MODULO 3: MOCK SCANNER (Simulatore) ---
def run_scan_simulation(target):
    """Esegue una scansione simulata per testare i moduli Grafico e AI."""
    print(Fore.YELLOW + f"[*] Scansione Target: {target}")
    
    # CORREZIONE ERRORE: Usiamo Style.DIM
    print(Style.DIM + "    -> Risoluzione DNS...") 
    time.sleep(1)
    print(Style.DIM + "    -> Port Scanning (Top 1000)...")
    time.sleep(2) 
    print(Style.DIM + "    -> Subdomain Enumeration...")
    time.sleep(1)
    
    # Dati generati per testare i moduli
    return {
        "target": target,
        "ip": "192.168.1.105",
        "ports": [80, 443, 22, 3306, 8080], 
        "subdomains": [f"www.{target}", f"api.{target}", f"dev.{target}", f"mail.{target}"]
    }

# --- MAIN CONTROLLER ---
def main():
    print(Fore.BLUE + Style.BRIGHT + """
    =========================================
      0xCONDOR RECON AUTOMATOR v2.1
      [+ NetworkX Graphs] [+ Llama 3 AI]
    =========================================
    """)
    
    parser = argparse.ArgumentParser(description="Automated Recon Tool")
    parser.add_argument("-t", "--target", help="Target domain (es. google.com)", required=True)
    args = parser.parse_args()
    
    target = args.target
    
    # 1. ESEGUI SCANSIONE (Simulata)
    scan_data = run_scan_simulation(target)
    
    print(Fore.WHITE + "\n--- RISULTATI SCANSIONE ---")
    print(f"Target: {scan_data['target']}")
    print(f"Porte Aperte: {scan_data['ports']}")
    
    # 2. ANALISI AI
    ai_report = analyze_with_ai(scan_data)
    
    # 3. GENERA GRAFICO
    generate_graph_networkx(scan_data['target'], scan_data['subdomains'], scan_data['ports'])
    
    # 4. STAMPA REPORT AI
    if ai_report:
        print(Fore.CYAN + "\n" + "="*40)
        print(Fore.CYAN + " REPORT AI (Llama 3) ")
        print(Fore.CYAN + "="*40 + Style.RESET_ALL)
        print(ai_report)
        
        # Salvataggio Report
        report_file = os.path.join(REPORTS_DIR, f"ai_report_{target}.md")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"# AI Recon Report for {target}\n\n")
            f.write(f"### Dati Rilevati:\n{json.dumps(scan_data, indent=2)}\n\n")
            f.write(f"### Analisi AI:\n{ai_report}")

        print(Style.DIM + f"\n[i] Report AI salvato in: {report_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Uscita forzata.")
