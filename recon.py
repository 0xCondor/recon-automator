#!/usr/bin/env python3
import sys
import asyncio
from recon_automator.interactive import main_interactive

# Se in futuro aggiungerai la CLI non-interattiva, potrai gestire qui gli argomenti
# from recon_automator.main import main_cli

def run():
    """
    Entry point principale per il tool ReconAutomator.
    """
    try:
        # Per ora lanciamo direttamente la modalità interattiva
        # In futuro qui potrai mettere un 'if args.interactive: ... else: ...'
        asyncio.run(main_interactive())
    except KeyboardInterrupt:
        print("\n[!] Interruzione utente. Uscita in corso...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Errore imprevisto: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run()