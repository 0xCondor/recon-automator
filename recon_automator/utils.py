import json
import os
from colorama import Fore, Style

CONFIG_FILE = "config.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass

def info(msg): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):  print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
