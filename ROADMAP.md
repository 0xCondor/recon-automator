# ROADMAP — ReconAutomator
Data: 21 ottobre 2025  
Autore: Daniel Filiu Mayedo (0xCondor)

---

Questo file raccoglie le idee, le priorità e i passi pratici per far evolvere ReconAutomator.
Non è una lista rigida: è una traccia di lavoro che possiamo aggiornare man mano.

---

## Obiettivi a breve termine (quick wins)
Cose da fare subito per migliorare l’esperienza e i report.

- **Web probe leggero**  
  Aggiungere un probe HTTP/HTTPS che verifichi status code, title e header per ogni host/subdomain trovato.  
- **Score Card leggibile**  
  Rendere il punteggio visibile nel report con una tabella e una breve spiegazione per i non tecnici.  
- **Export ordinato**  
  Salvare JSON e Markdown in `reports/` con nomi contenenti target e timestamp.  
- **Documentazione base**  
  Aggiornare README, aggiungere CONTRIBUTING.md e questo ROADMAP.md.

---

## Funzionalità da affrontare a medio termine
Più lavoro ma grande valore per i test.

- **Async / parallel scans**  
  Usare `asyncio` per le chiamate HTTP/API e threadpool per Nmap su più host. Riduce i tempi di esecuzione.  
- **Subdomain discovery avanzato**  
  Se i binari sono disponibili (`subfinder`, `amass`, `findomain`), usarli e parsificare i risultati. Fallback al metodo interno.  
- **Analisi passiva di JS**  
  Scaricare file JS pubblici, cercare pattern utili (endpoint, chiavi apparenti) con regex. Segnalare solo come "possibile" per evitare falsi positivi.  
- **Recon Graph interattivo**  
  Oltre al PNG con Graphviz, generare un HTML interattivo (pyvis) che si può esplorare nel browser.

---

## Idee per funzionalità avanzate (lunga scadenza)
Da pianificare e valutare con attenzione.

- **CASM (monitoring)**  
  Scheduler (cron) + notifica (Telegram/Discord/Slack) solo quando cambia qualcosa di importante (nuove porte, nuovo subdomain, aumento score).  
- **Integrazione Shodan / SecurityTrails / Wayback**  
  Aggiungere contesto esterno e storico per ogni IP/subdomain.  
- **Cloud discovery**  
  Controlli per bucket S3/Azure/GCS esposti usando pattern comuni. Documentare limiti e rischi delle richieste.  
- **Chaining verso altri tool**  
  Export in formati pronti per Nuclei, ffuf, masscan, ecc.

---

## Qualità del progetto e processo
Regole pratiche per mantenere il codice leggibile e collaborabile.

- **Tests**: aggiungere test unitari per parser nmap, scorecard e exporter (`pytest`).  
- **CI**: pipeline GitHub Actions per lint, test e build.  
- **Formattazione**: usare `black` e `isort`. Introdurre type hints dove sensato.  
- **CHANGELOG**: tenere traccia delle release in `CHANGELOG.md`.

---

## Flusso di lavoro consigliato (per ogni feature)
1. Crea branch: `feat/<descrizione>` (es. `feat/web-probe`).  
2. Implementa e testa localmente.  
3. Aggiungi test minimi.  
4. Apri PR con descrizione: cosa fa, come testare.  
5. Dopo merge, aggiorna CHANGELOG e ROADMAP.

---

## Piccoli passi pratici (per i prossimi 7 giorni)
- Completare `probes.py` e integrarlo in `core.run_scan`.  
- Aggiornare `requirements.txt` con `httpx` e `beautifulsoup4`.  
- Creare branch `feat/web-probe` e aprire PR quando pronto.  
- Aggiungere 1-2 screenshot nel README.

---

## Promozione e visibilità (breve)
- Mettere 1-2 screenshot nel README (menu, scorecard, graph).  
- Pubblicare un post breve su LinkedIn con 2 screenshot e link al repo.  
- Condividere in forum tecnici chiedendo feedback (r/netsec, r/cybersecurity).

---

## Nota legale e comportamento etico
Sempre ricordare: usare il tool solo su sistemi di tua proprietà o con permesso esplicito.  