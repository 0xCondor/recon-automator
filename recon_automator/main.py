import argparse
from .core import run_scan
from .utils import load_config, info, warn
from .report import print_report, export_json

def main():
    parser = argparse.ArgumentParser(description="ReconAutomator")
    parser.add_argument("--target", "-t", required=True, help="Dominio o IP da scannerizzare")
    parser.add_argument("--export", "-e", help="Esporta report JSON in questo file")
    args = parser.parse_args()

    api_keys = load_config()
    info(f"Risolvo {args.target}...")
    report = run_scan(args.target, api_keys)
    if not report:
        warn("Impossibile risolvere il target.")
        return

    print_report(report)
    if args.export:
        export_json(report, args.export)
        info(f"Report salvato in {args.export}")

if __name__ == "__main__":
    main()

