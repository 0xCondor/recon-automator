import os
from groq import Groq
from dotenv import load_dotenv

# Carica la chiave dal .env (assicurati di averla messa!)
load_dotenv()

def analyze_scan_results(scan_data):
    """
    Invia i dati della scansione a Llama 3 per un'analisi di sicurezza professionale.
    """
    api_key = os.getenv("GROQ_API_KEY")
    
    # Se l'utente non ha messo la chiave, saltiamo l'analisi senza crashare
    if not api_key:
        return "[INFO] API Key mancante. Analisi AI saltata."

    client = Groq(api_key=api_key)

    # Creiamo un riassunto dei dati per non intasare l'AI
    # (Assumiamo che scan_data sia il dizionario con i risultati di nmap/virustotal)
    target = scan_data.get('target', 'Sconosciuto')
    open_ports = scan_data.get('open_ports', [])
    subdomains = scan_data.get('subdomains', [])
    
    # Costruiamo il prompt per l'esperto di sicurezza
    system_prompt = """
    Sei un Senior Penetration Tester ed esperto di Cyber Security.
    Il tuo compito è analizzare i dati di ricognizione di un target e generare un report esecutivo.
    
    REGOLE:
    1. Identifica i rischi potenziali basandoti sulle porte aperte e i servizi.
    2. Suggerisci vettori di attacco specifici per le tecnologie rilevate.
    3. Sii conciso, professionale e usa un formato elenco puntato.
    4. Se non ci sono porte aperte, dai consigli generici di hardening.
    """

    user_message = f"""
    TARGET: {target}
    
    DATI RILEVATI:
    - Porte Aperte: {open_ports}
    - Sottodomini trovati: {len(subdomains)} (Esempi: {subdomains[:5]})
    
    Analizza questi dati e dimmi:
    1. Qual è il livello di rischio (Basso/Medio/Alto)?
    2. Quali sono i primi 3 test che dovrei fare manualmente?
    """

    try:
        print(f"\n[🤖] L'IA sta analizzando il target {target}...")
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            temperature=0.6,
            max_tokens=500
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"[ERRORE AI] Qualcosa è andato storto: {e}"